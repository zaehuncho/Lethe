"""Non-executing fixture checks for pinned prepared-evidence persistence."""
from __future__ import annotations

import copy
import importlib
import json
import os
from collections import Counter
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from packer import external_evidence_phase_b as phase_b
from packer import external_evidence_phase_c as phase_c
from packer import external_evidence_v2 as evidence
from test_external_evidence_v2 import (
    NOW, _phase_b_context, _phase_b_receipts, _test_authenticode, _test_candidate_verifier,
)

SNAPSHOT_MODULE = importlib.import_module('packer.pe_content_id')


def _read(path):
    return json.loads(path.read_bytes())


def _write(path, document):
    path.write_bytes(evidence.canonical_json_bytes(document))


def _reload(prepared, folder, **kwargs):
    return phase_c.load_prepared_bundle(
        folder, expected_context_id=prepared.context_id, now=kwargs.pop('now', NOW), **kwargs)


@pytest.fixture
def prepared_case(tmp_path):
    context = _phase_b_context(tmp_path / 'original-sources')
    prepared = context[0]
    folder = tmp_path / 'bundle'
    descriptor = phase_c.publish_prepared_bundle(prepared, folder, now=NOW)
    return context, prepared, folder, descriptor


def test_prepared_bundle_roundtrip_preserves_only_retained_material(prepared_case):
    context, prepared, folder, descriptor = prepared_case
    data = descriptor.read_bytes()
    document = _read(descriptor)
    assert data == evidence.canonical_json_bytes(document)
    assert document['schema'] == 1
    assert document['release_authorized'] is False
    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    assert all(str(context[-1][0].parent) not in value for value in strings(document))
    for record in document['files']:
        assert record['path'] == record['sha256'] + '.bin'
    loaded = _reload(prepared, folder)
    assert loaded.context_id == prepared.context_id
    assert loaded.challenge_bytes == prepared.challenge_bytes
    assert loaded.trust_bytes == prepared.trust_bytes
    assert loaded.candidate_verification == prepared.candidate_verification
    assert [(s.subject_id, s.subject_kind) for s in loaded.subjects] == [
        (s.subject_id, s.subject_kind) for s in prepared.subjects]
    original = phase_b._material(prepared)
    restored = phase_b._material(loaded)
    assert [(p, s.data, s.sha256, s.size) for p, s in restored] == [
        (p, s.data, s.sha256, s.size) for p, s in original]
    assert all(s.path.parent == folder for _, s in restored)
    assert all(s.path not in context[-1] for _, s in restored)


def test_prepared_roundtrip_supports_later_receipt_workflow(prepared_case, tmp_path):
    context, prepared, folder, _ = prepared_case
    loaded = _reload(prepared, folder)
    receipt_context = (loaded, *context[1:])
    receipts = _phase_b_receipts(receipt_context, tmp_path)
    final = phase_b.finalize_evidence(
        loaded, receipts, current_trust_document=context[2],
        authenticode_verifier=_test_authenticode, now=NOW)
    assert len(receipts) == 8
    assert final.context_id == prepared.context_id
    assert final.release_authorized is False


def test_publish_and_reload_never_reopen_original_sources(prepared_case, tmp_path, monkeypatch):
    context, prepared, _, _ = prepared_case
    for path in context[-1]:
        path.unlink(missing_ok=True)
    target = tmp_path / 'after-source-removal'
    descriptor = phase_c.publish_prepared_bundle(prepared, target, now=NOW)
    actual = phase_c.snapshot_file
    counts = Counter()

    def captured(path, **kwargs):
        path = Path(path).absolute()
        assert path.parent == target
        counts[path.name] += 1
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_c, 'snapshot_file', captured)
    loaded = _reload(prepared, target)
    expected_names = {'prepared.json', *[r['path'] for r in _read(descriptor)['files']]}
    assert set(counts) == expected_names
    assert set(counts.values()) == {1}
    assert loaded.context_id == prepared.context_id
    assert [s.data for _, s in phase_b._material(loaded)] == [
        s.data for _, s in phase_b._material(prepared)]


@pytest.mark.parametrize('content', ['shared-metadata', 'empty', 'trust-json'])
def test_digest_deduplication_reads_shared_content_once(prepared_case, tmp_path, monkeypatch, content):
    _, original, _, _ = prepared_case
    # Prepare again from sources with deliberately shared bytes, rather than
    # assuming the representative fixture happens to contain a duplicate.
    shared = {'shared-metadata': original.subjects[0].input.data,
              'empty': b'', 'trust-json': original.trust_bytes}[content]
    for subject in original.subjects:
        subject.input.path.write_bytes(shared)
    candidate = original.candidate
    prepared = phase_b.prepare_evidence(
        phase_b.CandidateInput(candidate.source_commit, candidate.stub.path,
                               candidate.manifest.path, candidate.production_native.path),
        [phase_b.SubjectInput(s.subject_id, s.subject_kind, s.unsigned.path,
                             s.input.path, s.pack_report.path, s.protection_profile.path)
         for s in original.subjects],
        json.loads(original.challenge_bytes)['requirements'], original.trust_bytes,
        candidate_verifier=_test_candidate_verifier, now=NOW)
    folder = tmp_path / 'deduplicated'
    descriptor = phase_c.publish_prepared_bundle(prepared, folder, now=NOW)
    records = _read(descriptor)['files']
    assert len({r['path'] for r in records}) < len(records)
    actual = phase_c.snapshot_file
    calls = Counter()
    budgets = {r['path']: max(1, r['size_bytes']) for r in records}
    budgets['prepared.json'] = 1048576

    def count(path, **kwargs):
        name = Path(path).name
        calls[name] += 1
        assert kwargs['max_bytes'] == budgets[name]
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_c, 'snapshot_file', count)
    loaded = _reload(prepared, folder)
    assert all(subject.input.data == shared for subject in loaded.subjects)
    assert all(count == 1 for count in calls.values())


def test_valid_descriptor_recomputes_phase_b_commitment(prepared_case):
    _, prepared, _, descriptor = prepared_case
    document = phase_c._decode_descriptor(descriptor.read_bytes())
    assert phase_c._descriptor_context_id(document) == phase_b._context_id(prepared)


def test_oversized_descriptor_is_rejected_without_reading_its_stream(prepared_case, monkeypatch):
    _, prepared, folder, descriptor = prepared_case
    descriptor.write_bytes(b' ' * (1048576 + 1))
    actual = SNAPSHOT_MODULE._open_snapshot_stream
    opened, reads, bounds = [], [], []
    capture = phase_c.snapshot_file

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, *args):
            reads.append(args)
            raise AssertionError('oversized descriptor must be rejected before a stream read')

    def open_stream(path, what):
        opened.append(Path(path))
        return Reader(actual(path, what))

    def snapshot(path, **kwargs):
        bounds.append(kwargs['max_bytes'])
        return capture(path, **kwargs)

    monkeypatch.setattr(SNAPSHOT_MODULE, '_open_snapshot_stream', open_stream)
    monkeypatch.setattr(phase_c, 'snapshot_file', snapshot)
    with pytest.raises(phase_c.PreparedBundleError, match='exceeds max_bytes'):
        _reload(prepared, folder)
    assert opened == [descriptor]
    assert reads == []
    assert bounds == [1048576]


@pytest.mark.parametrize('change', ['size', 'hash'])
def test_material_metadata_must_match_pin_before_any_artifact_snapshot(prepared_case, monkeypatch, change):
    _, prepared, folder, descriptor = prepared_case
    document = _read(descriptor)
    record = document['files'][-1]
    if change == 'size':
        record['size_bytes'] = 1 << 40  # Metadata only; no large file or allocation.
    else:
        record['sha256'] = 'a' * 64
        record['path'] = record['sha256'] + '.bin'
    _write(descriptor, document)
    actual = phase_c.snapshot_file
    captured = []

    def capture(path, **kwargs):
        captured.append(Path(path).name)
        assert Path(path).name == 'prepared.json', 'artifact read preceded metadata-pin check'
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_c, 'snapshot_file', capture)
    with pytest.raises(phase_c.PreparedBundleError, match='metadata does not match the expected external pin'):
        _reload(prepared, folder)
    assert captured == ['prepared.json']


@pytest.mark.parametrize('field', ['source_commit', 'candidate_stub_sha256',
                                    'candidate_manifest_sha256', 'production_native_sha256'])
def test_candidate_metadata_bindings_are_checked_before_artifact_snapshot(prepared_case, monkeypatch, field):
    _, prepared, folder, descriptor = prepared_case
    document = _read(descriptor)
    if field == 'source_commit':
        document['candidate']['source_commit'] = 'a' * 40
    else:
        document['candidate_verification'][field] = 'a' * 64
    _write(descriptor, document)
    actual = phase_c.snapshot_file
    captured = []

    def capture(path, **kwargs):
        captured.append(Path(path).name)
        assert Path(path).name == 'prepared.json'
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_c, 'snapshot_file', capture)
    with pytest.raises(phase_c.PreparedBundleError, match='candidate verification and material bindings'):
        _reload(prepared, folder)
    assert captured == ['prepared.json']


@pytest.mark.parametrize('purpose_index', [0, 1])
@pytest.mark.parametrize('size', [0, -1, 1 << 40])
def test_challenge_trust_sizes_have_independent_pre_read_json_bounds(prepared_case, monkeypatch, purpose_index, size):
    _, prepared, folder, descriptor = prepared_case
    document = _read(descriptor)
    # These sizes are not included in Phase B's metadata-context formula.
    document['files'][purpose_index]['size_bytes'] = size
    _write(descriptor, document)
    actual = phase_c.snapshot_file
    captured = []

    def capture(path, **kwargs):
        captured.append(Path(path).name)
        assert Path(path).name == 'prepared.json'
        return actual(path, **kwargs)

    monkeypatch.setattr(phase_c, 'snapshot_file', capture)
    with pytest.raises(phase_c.PreparedBundleError):
        _reload(prepared, folder)
    assert captured == ['prepared.json']


@pytest.mark.parametrize('which', ['root', 'ancestor', 'artifact'])
def test_reload_rejects_reparse_attributes(prepared_case, monkeypatch, which):
    _, prepared, folder, descriptor = prepared_case
    target = {'root': folder, 'ancestor': folder.parent,
              'artifact': folder / _read(descriptor)['files'][0]['path']}[which]
    actual = Path.lstat

    def lstat(path):
        info = actual(path)
        if path == target:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(phase_c.PreparedBundleError, match='reparse'):
        _reload(prepared, folder)


def test_reload_rejects_junction_flag(prepared_case, monkeypatch):
    _, prepared, folder, _ = prepared_case
    actual = getattr(Path, 'is_junction', lambda path: False)
    monkeypatch.setattr(Path, 'is_junction', lambda path: path == folder or actual(path), raising=False)
    with pytest.raises(phase_c.PreparedBundleError, match='junction'):
        _reload(prepared, folder)


def test_reload_requires_external_pin_and_current_challenge(prepared_case):
    _, prepared, folder, _ = prepared_case
    with pytest.raises(TypeError):
        phase_c.load_prepared_bundle(folder, now=NOW)
    with pytest.raises(phase_c.PreparedBundleError):
        phase_c.load_prepared_bundle(folder, expected_context_id='0' * 64, now=NOW)
    with pytest.raises(phase_c.PreparedBundleError):
        phase_c.load_prepared_bundle(folder, expected_context_id='f' * 64, now=NOW)
    with pytest.raises(phase_c.PreparedBundleError, match='expired'):
        _reload(prepared, folder, now=NOW + timedelta(days=2))


@pytest.mark.parametrize('change', [
    'extra-top', 'authority', 'float-schema', 'duplicate-subject', 'wrong-kind',
    'reorder-subjects', 'extra-file', 'missing-file', 'duplicate-purpose',
    'reorder-files', 'float-size', 'traversal', 'absolute', 'case-name',
    'wrong-candidate', 'wrong-verifier', 'invalid-verifier', 'verifier-extra', 'wrong-size',
])
def test_reload_rejects_descriptor_inconsistencies(prepared_case, change):
    _, prepared, folder, descriptor = prepared_case
    document = _read(descriptor)
    if change == 'extra-top': document['extra'] = 1
    elif change == 'authority': document['release_authorized'] = True
    elif change == 'float-schema': document['schema'] = 1.0
    elif change == 'duplicate-subject': document['subjects'][1] = copy.deepcopy(document['subjects'][0])
    elif change == 'wrong-kind': document['subjects'][1]['subject_kind'] = 'exe'
    elif change == 'reorder-subjects': document['subjects'].reverse()
    elif change == 'extra-file': document['files'].append(copy.deepcopy(document['files'][0]))
    elif change == 'missing-file': document['files'].pop()
    elif change == 'duplicate-purpose': document['files'][1]['purpose'] = document['files'][0]['purpose']
    elif change == 'reorder-files': document['files'][0], document['files'][1] = document['files'][1], document['files'][0]
    elif change == 'float-size': document['files'][0]['size_bytes'] = float(document['files'][0]['size_bytes'])
    elif change == 'traversal': document['files'][0]['path'] = '../outside.bin'
    elif change == 'absolute': document['files'][0]['path'] = 'C:/outside.bin'
    elif change == 'case-name': document['files'][0]['path'] = document['files'][0]['path'].upper()
    elif change == 'wrong-candidate': document['candidate']['source_commit'] = 'a' * 40
    elif change == 'wrong-verifier': document['candidate_verification']['verifier_id'] = 'different-verifier'
    elif change == 'invalid-verifier': document['candidate_verification']['valid'] = False
    elif change == 'verifier-extra': document['candidate_verification']['unbound'] = 'extra'
    elif change == 'wrong-size': document['files'][0]['size_bytes'] += 1
    _write(descriptor, document)
    with pytest.raises(phase_c.PreparedBundleError):
        _reload(prepared, folder)


@pytest.mark.parametrize('change', ['duplicate-key', 'whitespace', 'oversize'])
def test_reload_rejects_noncanonical_or_unbounded_json(prepared_case, change):
    _, prepared, folder, descriptor = prepared_case
    data = descriptor.read_bytes()
    if change == 'duplicate-key': data = b'{"schema":1,' + data[1:]
    elif change == 'whitespace': data = b' ' + data
    else: data = b' ' * 1048577
    descriptor.write_bytes(data)
    with pytest.raises(phase_c.PreparedBundleError):
        _reload(prepared, folder)


@pytest.mark.parametrize('change', ['extra-file', 'extra-directory', 'missing-artifact', 'missing-descriptor', 'tamper', 'size'])
def test_reload_rejects_actual_file_set_or_bytes(prepared_case, change):
    _, prepared, folder, descriptor = prepared_case
    records = _read(descriptor)['files']
    artifact = folder / records[0]['path']
    if change == 'extra-file': (folder / 'unexpected.bin').write_bytes(b'extra')
    elif change == 'extra-directory': (folder / 'unexpected').mkdir()
    elif change == 'missing-artifact': artifact.unlink()
    elif change == 'missing-descriptor': descriptor.unlink()
    elif change == 'tamper':
        data = artifact.read_bytes()
        artifact.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == 'size': artifact.write_bytes(artifact.read_bytes() + b'changed')
    with pytest.raises(phase_c.PreparedBundleError):
        _reload(prepared, folder)


@pytest.mark.parametrize('which', ['artifact', 'descriptor'])
def test_reload_rejects_hardlinked_files(prepared_case, tmp_path, which):
    _, prepared, folder, descriptor = prepared_case
    target = descriptor if which == 'descriptor' else folder / _read(descriptor)['files'][0]['path']
    try:
        os.link(target, tmp_path / 'outside-hardlink')
    except OSError as exc:
        pytest.skip(f'hardlink unavailable: {exc}')
    with pytest.raises(phase_c.PreparedBundleError, match='hard'):
        _reload(prepared, folder)


@pytest.mark.parametrize('which', ['artifact', 'descriptor', 'root', 'ancestor'])
def test_reload_rejects_symlink_paths(prepared_case, tmp_path, which):
    _, prepared, folder, descriptor = prepared_case
    try:
        if which in {'artifact', 'descriptor'}:
            target = descriptor if which == 'descriptor' else folder / _read(descriptor)['files'][0]['path']
            outside = tmp_path / 'external-file'
            outside.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(outside)
            load_root = folder
        elif which == 'root':
            load_root = tmp_path / 'linked-bundle'
            load_root.symlink_to(folder, target_is_directory=True)
        else:
            parent_alias = tmp_path / 'linked-parent'
            parent_alias.symlink_to(tmp_path, target_is_directory=True)
            load_root = parent_alias / folder.name
    except OSError as exc:
        pytest.skip(f'symlink unavailable: {exc}')
    with pytest.raises(phase_c.PreparedBundleError):
        _reload(prepared, load_root)


def test_inventory_rejects_case_alias_even_on_casefolding_filesystems(prepared_case, monkeypatch):
    _, prepared, folder, descriptor = prepared_case
    existing = list(folder.iterdir())
    artifact = folder / _read(descriptor)['files'][0]['path']
    alias = artifact.with_name(artifact.name.upper())
    original_iterdir, original_lstat = Path.iterdir, Path.lstat
    monkeypatch.setattr(Path, 'iterdir', lambda p: iter([*existing, alias]) if p == folder else original_iterdir(p))
    monkeypatch.setattr(Path, 'lstat', lambda p: original_lstat(artifact) if p == alias else original_lstat(p))
    with pytest.raises(phase_c.PreparedBundleError, match='alias'):
        _reload(prepared, folder)


def test_reload_detects_membership_change_during_capture(prepared_case, monkeypatch):
    _, prepared, folder, _ = prepared_case
    actual = phase_c.snapshot_file
    changed = False

    def capture(path, **kwargs):
        nonlocal changed
        result = actual(path, **kwargs)
        if not changed and Path(path).name != 'prepared.json':
            changed = True
            (folder / 'late-extra.bin').write_bytes(b'late')
        return result

    monkeypatch.setattr(phase_c, 'snapshot_file', capture)
    with pytest.raises(phase_c.PreparedBundleError, match='changed'):
        _reload(prepared, folder)


def test_reload_detects_identity_change_with_same_membership(prepared_case, monkeypatch):
    _, prepared, folder, _ = prepared_case
    actual = phase_c._inventory
    calls = 0

    def inventory(path):
        nonlocal calls
        calls += 1
        identity, names = actual(path)
        if calls == 2:
            identity = (identity[0], identity[1] + 1, *identity[2:])
        return identity, names

    monkeypatch.setattr(phase_c, '_inventory', inventory)
    with pytest.raises(phase_c.PreparedBundleError, match='identity or membership changed'):
        _reload(prepared, folder)


def test_publication_never_clobbers_and_marker_is_last(prepared_case, tmp_path, monkeypatch):
    _, prepared, folder, _ = prepared_case
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    with pytest.raises(phase_c.PreparedBundleError):
        phase_c.publish_prepared_bundle(prepared, folder, now=NOW)
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before
    empty = tmp_path / 'existing-empty'
    empty.mkdir()
    with pytest.raises(phase_c.PreparedBundleError):
        phase_c.publish_prepared_bundle(prepared, empty, now=NOW)
    assert not list(empty.iterdir())
    order = []
    actual = phase_c._write_exclusive

    def write(path, data):
        order.append(path.name)
        return actual(path, data)

    monkeypatch.setattr(phase_c, '_write_exclusive', write)
    phase_c.publish_prepared_bundle(prepared, tmp_path / 'ordered', now=NOW)
    assert order[-1] == 'prepared.json'
    assert order.count('prepared.json') == 1


def test_failed_publish_retains_partial_without_completion_marker(prepared_case, tmp_path, monkeypatch):
    _, prepared, _, _ = prepared_case
    target = tmp_path / 'incomplete'

    def fail_write(path, data):
        raise OSError('simulated storage failure')

    monkeypatch.setattr(phase_c, '_write_exclusive', fail_write)
    with pytest.raises(phase_c.PreparedBundleError):
        phase_c.publish_prepared_bundle(prepared, target, now=NOW)
    assert target.is_dir()
    assert not (target / 'prepared.json').exists()


def test_invalid_context_does_not_create_output(prepared_case, tmp_path):
    _, prepared, _, _ = prepared_case
    target = tmp_path / 'bad-context'
    with pytest.raises(phase_c.PreparedBundleError):
        phase_c.publish_prepared_bundle(replace(prepared, context_id='f' * 64), target, now=NOW)
    assert not target.exists()
