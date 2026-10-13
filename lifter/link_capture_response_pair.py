"""Fail-closed response/input parity for two conventional LINKREPRO captures.

This re-runs selected-reference and object-omission proofs against the current
capture bytes.  It is a link *input* prerequisite only: it cannot prove
archive extraction, PE output equivalence, indirect targets, or production use.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

from .link_capture_archive import (
    CaptureClosureError, _capture_regular_file, _capture_root, _capture_token,
)
from .link_capture_selected_references import (
    SelectedReferenceError, inspect_replacement_omission, inspect_selected_capture,
)
from .source_link_product_admission import ProductSourceInputs


class ResponsePairError(ValueError):
    """Two captured link invocations cannot be bounded as an exact pair."""


_INPUT = re.compile(r"\.\\[A-Za-z0-9_.@+\-$]+\.(?:obj|lib|res)\Z", re.I)
_PDBMAP = re.compile(
    r"/pdbmap:([A-Za-z]:\\[^=]+)=(\.\\[A-Za-z0-9_.@+\-$]+\.pdb)\Z", re.I
)
_OUTPUT_PDB = re.compile(r"/pdb:(\.\\[A-Za-z0-9_.@+\-$]+\.pdb)\Z", re.I)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = ("/LTCG", "/WHOLEARCHIVE", "/INCLUDE:", "/ALTERNATENAME:",
              "/DEFAULTLIB:", "/ORDER:", "/DEF:", "/FORCE", "/MERGE:")
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_()]*\Z")
_ENV_DRIVE = re.compile(r"=([A-Za-z]):=(.+)\Z")
_ENV_HIDDEN = re.compile(r"=([A-Za-z_][A-Za-z0-9_()]*)=(.*)\Z")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ResponsePairError(reason)


def _sha(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _read_response(root: Path) -> tuple[str, tuple[str, ...]]:
    try:
        raw = _capture_regular_file(root, "link.rsp")
    except CaptureClosureError as exc:
        raise ResponsePairError(str(exc)) from exc
    _require(raw.startswith(b"\xff\xfe") and len(raw) <= 512 * 1024,
             "LINKREPRO response encoding or size is unsupported")
    try:
        decoded = raw.decode("utf-16")
        _require(decoded.endswith("\r\n") and
                 all("\r" not in line and "\n" not in line and
                     not any(c in line for c in "\x00\x85\u2028\u2029")
                     for line in decoded.split("\r\n")[:-1]),
                 "LINKREPRO response line separators are unsupported")
        lines = decoded.split("\r\n")[:-1]
        tokens = tuple(_capture_token(line) for line in lines)
    except (UnicodeError, CaptureClosureError) as exc:
        raise ResponsePairError("LINKREPRO response has malformed quoted tokens") from exc
    _require(0 < len(tokens) <= 2048 and all(len(token) <= 4096 for token in tokens),
             "LINKREPRO response token count or length is unsupported")
    return _sha(raw), tokens


def _environment_profile(root: Path) -> tuple[str, tuple[tuple[str, str], ...], bool]:
    """Bind the captured environment without equating capture-local paths.

    LINK_REPRO must name this exact capture.  The working-directory drive entry
    may differ between two link invocations only inside their common evidence
    root.  Neither exception proves linker environment or CWD semantics.
    """
    try:
        raw = _capture_regular_file(root, "env.setting")
    except CaptureClosureError as exc:
        raise ResponsePairError("LINKREPRO environment record is missing or redirected") from exc
    _require(0 < len(raw) <= 64 * 1024,
             "LINKREPRO environment record size is unsupported")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ResponsePairError("LINKREPRO environment record is not UTF-8") from exc
    _require(decoded.endswith("\r\n") and "\x00" not in decoded and
             all("\r" not in line and "\n" not in line
                 for line in decoded.split("\r\n")[:-1]),
             "LINKREPRO environment line separators are unsupported")
    rows: dict[str, str] = {}
    local_drive = False
    link_repro = False
    for line in decoded.split("\r\n")[:-1]:
        drive = _ENV_DRIVE.fullmatch(line) if line.startswith("=") else None
        if drive is not None:
            key, value = "=" + drive.group(1).upper() + ":", drive.group(2)
            _require(Path(value).is_absolute() and
                     Path(value).drive.casefold() == key[1:].casefold() and
                     ".." not in Path(value).parts,
                     "LINKREPRO drive working directory is unsupported")
            if key[1:].casefold() == root.drive.casefold():
                try:
                    Path(value).resolve(strict=True).relative_to(root.parent.parent)
                except (OSError, ValueError) as exc:
                    raise ResponsePairError(
                        "LINKREPRO local working directory escapes evidence root") from exc
                local_drive = True
                value = "<CAPTURE_LOCAL_WORKING_DIRECTORY>"
        elif line.startswith("="):
            # CMD also emits hidden non-drive records such as =ExitCode.
            # They are retained byte-for-byte in the compared profile.
            hidden = _ENV_HIDDEN.fullmatch(line)
            _require(hidden is not None,
                     "LINKREPRO hidden environment entry is malformed")
            key, value = "=" + hidden.group(1), hidden.group(2)
        else:
            _require("=" in line and not line.startswith("="),
                     "LINKREPRO environment entry is malformed")
            key, value = line.split("=", 1)
            _require(_ENV_KEY.fullmatch(key) is not None,
                     "LINKREPRO environment key or value is unsupported")
            if key.casefold() == "link_repro":
                _require(value.casefold() == str(root).casefold(),
                         "LINKREPRO environment capture path differs")
                link_repro = True
                value = "<THIS_CAPTURE_ROOT>"
        folded = key.casefold()
        _require(folded not in rows,
                 "LINKREPRO environment key is case-ambiguous")
        rows[folded] = value
    _require(link_repro, "LINKREPRO environment capture path is missing")
    return _sha(raw), tuple(sorted(rows.items())), local_drive


def _profile(root: Path, tokens: tuple[str, ...]) -> tuple[tuple[str, ...],
                                                          tuple[str, ...],
                                                          dict[str, str],
                                                          tuple[tuple[str, str], ...]]:
    profile: list[str] = []
    inputs: list[str] = []
    mapped_pdb: dict[str, str] = {}
    pdbmap_rows: list[tuple[str, str]] = []
    for token in tokens:
        if token.startswith("/"):
            upper = token.upper()
            _require(not any(upper.startswith(prefix) for prefix in _FORBIDDEN),
                     "LINKREPRO response has an unsupported linker option")
            if upper.startswith("/PDBMAP:"):
                match = _PDBMAP.fullmatch(token)
                _require(match is not None,
                         "LINKREPRO PDBMAP is malformed or external")
                source, mapped = match.groups()
                _require(".." not in Path(source).parts and
                         not any(c in source for c in "%!&^|<>") and
                         ".." not in mapped,
                         "LINKREPRO PDBMAP source is ambiguous")
                name = mapped[2:]
                try:
                    raw = _capture_regular_file(root, name)
                except CaptureClosureError as exc:
                    raise ResponsePairError(str(exc)) from exc
                _require(len(raw) <= 64 * 1024 * 1024,
                         "LINKREPRO captured PDBMAP payload is excessive")
                digest = _sha(raw)
                old = mapped_pdb.setdefault(name.casefold(), digest)
                _require(old == digest, "LINKREPRO PDBMAP payload conflicts")
                # LINKREPRO may insert its capture-generated PDBMAP beside
                # different inputs on repeated links. Compare its exact
                # captured payload and multiplicity separately; do not claim
                # PDBMAP token-position equivalence.
                pdbmap_rows.append((name.casefold(), digest))
            else:
                profile.append(token)
            continue
        _require(bool(_INPUT.fullmatch(token)) and ".." not in token,
                 "LINKREPRO input token is unsupported")
        inputs.append(token)
        profile.append(token)
    _require(bool(inputs), "LINKREPRO response has no material inputs")
    _require(len({name.casefold() for name in inputs}) <= 256,
             "LINKREPRO response input inventory is excessive")
    return tuple(profile), tuple(inputs), mapped_pdb, tuple(sorted(pdbmap_rows))


def _output_pdb_name(tokens: tuple[str, ...], mapped_pdb: dict[str, str]) -> str | None:
    names = [match.group(1)[2:] for token in tokens
             if (match := _OUTPUT_PDB.fullmatch(token)) is not None]
    _require(len(names) <= 1 and
             (not names or names[0].casefold() not in mapped_pdb),
             "LINKREPRO output PDB is repeated or overlaps mapped input PDB")
    return names[0] if names else None


def inspect_response_pair(
    original_capture: Path,
    replacement_capture: Path,
    inputs: ProductSourceInputs,
    *,
    expected_selected: dict | None = None,
    expected_omission: dict | None = None,
) -> dict:
    """Check unchanged link options/order and all captured input bytes.

    PDBMAP source paths/positions may move between build directories only when
    capture-local payload names, hashes and multiplicity match.  Their source
    path semantics, the linker executable and final outputs remain unproven.
    """
    _require(type(inputs) is ProductSourceInputs,
             "exact source input contract is required")
    try:
        original_selected = inspect_selected_capture(Path(original_capture), inputs)
        replacement_omission = inspect_replacement_omission(
            original_selected, Path(replacement_capture)
        )
    except SelectedReferenceError as exc:
        raise ResponsePairError(f"fresh selected/omission proof failed: {exc}") from exc
    if expected_selected is not None:
        _require(type(expected_selected) is dict and expected_selected == original_selected,
                 "stale or forged selected-reference report")
    if expected_omission is not None:
        _require(type(expected_omission) is dict and expected_omission == replacement_omission,
                 "stale or forged omission report")
    _require(original_selected.get("selected_input_references_classified") is True
             and replacement_omission.get("original_helper_object_omission_proven") is True
             and replacement_omission.get("other_input_hashes_equal") is True,
             "selected/omission prerequisite is missing")
    helper = original_selected.get("helper_object")
    expected = original_selected.get("capture_input_hashes")
    old_hash = original_selected.get("source_coff_sha256")
    new_hash = replacement_omission.get("replacement_coff_sha256")
    _require(type(helper) is str and helper.lower().endswith(".obj")
             and bool(_INPUT.fullmatch(".\\" + helper))
             and type(expected) is dict and bool(expected)
             and all(type(k) is str and type(v) is str and _DIGEST.fullmatch(v)
                     for k, v in expected.items())
             and len({k.casefold() for k in expected}) == len(expected)
             and type(old_hash) is str and bool(_DIGEST.fullmatch(old_hash))
             and type(new_hash) is str and bool(_DIGEST.fullmatch(new_hash))
             and old_hash != new_hash and expected.get(helper) == old_hash
             and replacement_omission.get("original_coff_sha256") == old_hash,
             "selected helper/input hash provenance is malformed")
    try:
        before_root = _capture_root(Path(original_capture))
        after_root = _capture_root(Path(replacement_capture))
    except CaptureClosureError as exc:
        raise ResponsePairError(str(exc)) from exc
    before_rsp, before_tokens = _read_response(before_root)
    after_rsp, after_tokens = _read_response(after_root)
    _require(before_rsp == original_selected.get("capture_rsp_sha256")
             and after_rsp == replacement_omission.get("replacement_rsp_sha256"),
             "LINKREPRO response differs from selected/omission reports")
    before_opts, before_inputs, before_pdb, before_rows = _profile(before_root, before_tokens)
    after_opts, after_inputs, after_pdb, after_rows = _profile(after_root, after_tokens)
    _require(before_inputs == after_inputs,
             "LINKREPRO material input order differs")
    _require(before_opts == after_opts,
             "LINKREPRO linker options differ between original and replacement")
    _require(before_pdb == after_pdb and before_rows == after_rows,
             "LINKREPRO captured PDBMAP payload differs")
    before_output_pdb = _output_pdb_name(before_tokens, before_pdb)
    after_output_pdb = _output_pdb_name(after_tokens, after_pdb)
    _require(before_output_pdb == after_output_pdb,
             "LINKREPRO output PDB option differs")
    explicit = original_selected.get("response_input_hashes", expected)
    implicit = original_selected.get("implicit_library_hashes", {})
    _require(type(explicit) is dict and type(implicit) is dict and
             not set(explicit).intersection(implicit) and
             expected == {**explicit, **implicit} and
             set(explicit) == set(name[2:] for name in before_inputs),
             "LINKREPRO explicit/implicit input inventory differs from source report")
    _require(implicit == replacement_omission.get(
                 "replacement_implicit_library_hashes", implicit),
             "LINKREPRO captured implicit libraries differ")
    seen: set[str] = set()
    for token in before_inputs:
        name = token[2:]
        if name in seen:
            continue
        seen.add(name)
        try:
            old_raw = _capture_regular_file(before_root, name)
            new_raw = _capture_regular_file(after_root, name)
        except CaptureClosureError as exc:
            raise ResponsePairError(str(exc)) from exc
        _require(_sha(old_raw) == expected[name],
                 "original LINKREPRO material input changed")
        _require(_sha(new_raw) == (new_hash if name == helper else expected[name]),
                 "replacement LINKREPRO material input changed")
    for name, digest in implicit.items():
        _require(bool(_INPUT.fullmatch(".\\" + name)) and name.lower().endswith(".lib") and
                 _sha(_capture_regular_file(before_root, name)) == digest and
                 _sha(_capture_regular_file(after_root, name)) == digest,
                 "LINKREPRO captured implicit library changed")
    before_env_sha, before_env_profile, before_local = _environment_profile(before_root)
    after_env_sha, after_env_profile, after_local = _environment_profile(after_root)
    _require(before_env_profile == after_env_profile and before_local == after_local,
             "LINKREPRO captured environment profile differs")
    before_files = original_selected.get("capture_file_sha256", {})
    after_files = replacement_omission.get("replacement_capture_file_sha256", {})
    before_roles = original_selected.get("capture_file_roles", {})
    after_roles = replacement_omission.get("replacement_capture_file_roles", {})
    if before_files or after_files:
        _require(type(before_files) is dict and type(after_files) is dict and
                 all(type(name) is str and type(digest) is str and
                     _DIGEST.fullmatch(digest) for files in (before_files, after_files)
                     for name, digest in files.items()) and
                 before_files.get("env.setting") == before_env_sha and
                 after_files.get("env.setting") == after_env_sha and
                 set(before_files) == set(after_files),
                 "LINKREPRO captured file inventory differs")
        _require(all(before_files[name] == after_files[name]
                     for name in before_files
                     if name not in (helper, "link.rsp", "env.setting",
                                     before_output_pdb)),
                 "LINKREPRO captured non-helper file changed")
        _require(type(before_roles) is dict and type(after_roles) is dict and
                 before_roles == after_roles and
                 set(before_roles) == set(before_files),
                 "LINKREPRO captured file roles differ")
        if before_output_pdb is not None:
            _require(before_roles.get(before_output_pdb) ==
                     "pdb_metadata_not_coff_input",
                     "LINKREPRO output PDB file role differs")
        for root, files in ((before_root, before_files), (after_root, after_files)):
            for name, digest in files.items():
                try:
                    actual = _sha(_capture_regular_file(root, name))
                except CaptureClosureError as exc:
                    raise ResponsePairError(
                        "LINKREPRO capture file changed during final re-read") from exc
                _require(actual == digest,
                         "LINKREPRO capture file changed during final re-read")
    return {
        "schema": 1,
        "status": "captured_response_and_inputs_paired",
        "selected": original_selected.get("selected"),
        "original_rsp_sha256": before_rsp,
        "replacement_rsp_sha256": after_rsp,
        "input_occurrences": len(before_inputs),
        "distinct_inputs": len(seen),
        "captured_implicit_libraries": len(implicit),
        "captured_implicit_library_hashes": dict(sorted(implicit.items())),
        "captured_implicit_libraries_equal": True,
        "captured_file_count": len(before_files),
        "captured_file_roles": dict(sorted(before_roles.items())),
        "original_env_setting_sha256": before_env_sha,
        "replacement_env_setting_sha256": after_env_sha,
        "environment_equal_except_bound_capture_local_paths": True,
        "environment_working_directory_semantics_proven": False,
        "captured_output_pdb": before_output_pdb,
        "captured_output_pdb_equal": None if before_output_pdb is None else (
            before_files.get(before_output_pdb) == after_files.get(before_output_pdb)),
        "captured_output_pdb_semantics_proven": False,
        "capture_read_race_eliminated": False,
        "captured_pdbmap_payloads": dict(sorted(before_pdb.items())),
        "pdbmap_option_count": len(before_rows),
        "response_profile_equal_except_pdbmap_source_and_position": True,
        "capture_pdbmap_option_position_proven": False,
        "capture_pdbmap_source_path_proven": False,
        "response_option_semantics_proven": False,
        "implicit_coff_directives_bound": False,
        "external_default_library_resolution_bound": False,
        "selected_input_references_classified": True,
        "original_helper_object_omission_proven": True,
        "all_nonhelper_input_hashes_equal": True,
        "helper_changed_and_original_omitted_from_capture": True,
        "linker_executable_bound": False,
        "archive_member_extraction_proven": False,
        "source_output_reference_equivalence_proven": False,
        "final_image_reference_closure_proven": False,
        "indirect_target_closure_proven": False,
        "xfg_enforcement_proven": False,
        "production_admitted": False,
    }


__all__ = ["ResponsePairError", "inspect_response_pair"]
