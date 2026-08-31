"""
Lethe -- top-level orchestration: the ONE API both front-ends call.

The PySide6 GUI (``gui/app.py``) and the CLI (``lethe.py``) are thin wrappers
over :func:`pack_file` so they can never drift. The pipeline drop-in
(``pack_lethe_release.py --packer-command``) ultimately calls the CLI, which
calls this.

Flow:  analyze  ->  build_payload  ->  assemble  ->  (write on disk)
Every stage reports through an optional ``progress(str)`` callback. Nothing is
allowed to raise past this boundary: any failure becomes ``PackResult(ok=False,
error=...)`` so a batch GUI run keeps going and the CLI can print a clean error.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import struct
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from typing import Callable, Optional
from urllib.parse import urlparse

# IMAGE_FILE_DLL bit in the COFF file-header Characteristics field.
_IMAGE_FILE_DLL = 0x2000

# Expected hostname for the shard upload API. A misrouted shard upload permanently
# bricks the packed binary (it is keyed to a shard the real server never receives),
# so a hostname mismatch HARD-FAILS the pack. Override only with an explicit
# allow_unpinned_host / --allow-unpinned-host (e.g. a staging host).
_SHARD_API_HOST = "shard.example.invalid"
_MAX_SHARD_RESPONSE = 64 * 1024


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward shard credentials to a redirected request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_shard_request(req: urllib.request.Request, *,
                        context: ssl.SSLContext, timeout: int):
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _RejectRedirects(),
    )
    return opener.open(req, timeout=timeout)


@dataclass
class PackOptions:
    """User-facing knobs (global, with per-file override in the GUI)."""
    anti_debug: bool = False
    memory_guard: bool = False          # opt-in; AV-test first (see plan §8)
    compression_level: int = 9
    output_path: Optional[str] = None   # default: <input>.packed<ext>
    is_dll: Optional[bool] = None       # None => auto-detect from the PE header
    server_shard: bool = False          # Tier 3: XOR a server-held shard into the key
    shard_url: Optional[str] = None     # experimental shard gate base URL
    shard_auth: Optional[str] = None    # Bearer token for shard upload
    shard_license_id: Optional[str] = None   # bind shard to a specific license
    shard_hwid_hash: Optional[str] = None    # SHA-256 hex of target machine HWID
    shard_max_activations: int = 0           # 0 = unlimited
    shard_ttl_hours: int = 0                 # 0 = no expiry
    allow_unpinned_host: bool = False        # allow a shard_url host != _SHARD_API_HOST
    shard_pin_pem: Optional[str] = None      # path to a pinned leaf/CA PEM (true TLS pin)
    stub_path: Optional[str] = None           # override prebuilt stub for validation


@dataclass
class PackResult:
    input_path: str
    output_path: Optional[str]
    ok: bool
    error: Optional[str]
    original_size: int
    packed_size: int
    ratio: float                        # packed / original (lower is better)
    elapsed_ms: float
    build_id: Optional[str] = None      # signing-stable SHA-256 PE content ID


ProgressFn = Optional[Callable[[str], None]]


def _emit(progress: ProgressFn, msg: str) -> None:
    if progress is not None:
        try:
            progress(msg)
        except Exception:
            pass                         # a noisy UI callback must never fail a pack


def _make_pinned_context(pin_pem: Optional[str] = None) -> ssl.SSLContext:
    """SSLContext for the shard upload.

    If ``pin_pem`` is given (a PEM file holding the shard API's leaf or issuing
    CA), trust ONLY that certificate -- true pinning: even a valid public-CA cert
    for the host is rejected, defeating a mis-issued-cert MITM. Otherwise fall
    back to the curated ``certifi`` CA bundle (CA-level trust, not leaf pinning),
    which still excludes rogue system-installed CAs. ``check_hostname`` stays on
    in both cases.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if pin_pem:
        # Trust ONLY the pinned leaf/CA. A wrong or unreadable pin must fail the
        # pack (ssl raises), never silently widen trust.
        ctx.load_verify_locations(cafile=pin_pem)
        return ctx
    # No explicit pin: curated CA bundle rather than the OS store, so a rogue
    # system-installed CA can't intercept. Set LETHE_SHARD_PIN_PEM (or PackOptions
    # .shard_pin_pem) to the deployment's leaf/CA for true pinning.
    try:
        import certifi
    except ImportError as exc:
        raise RuntimeError(
            "certifi is required for shard uploads unless shard_pin_pem is set; "
            "refusing to widen trust to the Windows system CA store") from exc
    ctx.load_verify_locations(certifi.where())
    return ctx


def _extract_error(raw: bytes) -> str:
    """Pull the ``error`` field out of a v2 error body, defensively."""
    try:
        return str(json.loads(raw).get("error", "no error field"))
    except (ValueError, TypeError, AttributeError):
        return "unparseable error body"


def _pe_content_id(path: str) -> str:
    """Return a signing-stable SHA-256 identifier for an x64 PE.

    The digest follows the Authenticode exclusion model: the mutable PE checksum,
    the certificate-table directory entry, and the certificate bytes themselves
    are omitted. Consequently the same packed image has the same ID before and
    after signing, while changes to executable content still change the ID.
    """
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path!r} is not a valid PE (missing DOS header)")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    file_header = e_lfanew + 4
    optional_header = file_header + 20
    if (e_lfanew + 24 > len(data)
            or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00"):
        raise ValueError(f"{path!r} is not a valid PE (missing PE signature)")

    (optional_size,) = struct.unpack_from("<H", data, file_header + 16)
    optional_end = optional_header + optional_size
    if optional_end > len(data) or optional_size < 0x98:
        raise ValueError(f"{path!r} has a truncated PE32+ optional header")
    if struct.unpack_from("<H", data, file_header)[0] != 0x8664:
        raise ValueError(f"{path!r} is not an AMD64 PE image")
    if struct.unpack_from("<H", data, optional_header)[0] != 0x20B:
        raise ValueError(f"{path!r} is not an x64 PE32+ image")

    checksum_off = optional_header + 0x40
    number_of_dirs = struct.unpack_from("<I", data, optional_header + 0x6C)[0]
    if number_of_dirs <= 4:
        raise ValueError(f"{path!r} has no certificate-table directory entry")
    security_dir_off = optional_header + 0x70 + (4 * 8)
    if security_dir_off + 8 > optional_end:
        raise ValueError(f"{path!r} has a truncated certificate-table directory")

    cert_off, cert_size = struct.unpack_from("<II", data, security_dir_off)
    after_security_dir = security_dir_off + 8
    if bool(cert_off) != bool(cert_size):
        raise ValueError(f"{path!r} has an invalid certificate-table range")
    if cert_off:
        cert_end = cert_off + cert_size
        if cert_off < after_security_dir or cert_end > len(data):
            raise ValueError(f"{path!r} has an out-of-range certificate table")
    else:
        cert_end = 0

    digest = hashlib.sha256()
    digest.update(data[:checksum_off])
    digest.update(data[checksum_off + 4:security_dir_off])
    if cert_off:
        digest.update(data[after_security_dir:cert_off])
        digest.update(data[cert_end:])
    else:
        digest.update(data[after_security_dir:])
    return digest.hexdigest()


def _validate_build_id(build_id: str) -> str:
    normalized = build_id.strip().lower()
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise ValueError("build_id must be a 64-character SHA-256 PE content ID")
    return normalized


def _upload_shard(shard: bytes, *, build_id: str, url: str, auth: str,
                  license_id: str = "", hwid_hash: str = "",
                  max_activations: int = 0, ttl_hours: int = 0,
                  allow_unpinned_host: bool = False,
                  pin_pem: Optional[str] = None,
                  progress: ProgressFn = None) -> dict:
    """Upload a build's server shard to the Lambda shard gate (POST /api/shard/store).

    The shard is sent hex-encoded and bound to ``license_id`` + ``hwid_hash``
    under the signing-stable SHA-256 PE content ``build_id``. The server
    encrypts it at rest
    and returns ``{ok, build_id, expires_at}``. Raises on any non-success so the
    caller can delete the half-baked output (a shard that never reached the
    server leaves the packed binary permanently unrunnable).
    """
    build_id = _validate_build_id(build_id)
    if len(shard) != 32:
        raise ValueError("server shard must be exactly 32 bytes")
    if not auth.strip():
        raise ValueError("shard upload authentication token must not be empty")
    if max_activations < 0 or ttl_hours < 0:
        raise ValueError("shard activation and TTL limits must be non-negative")
    # --- HTTPS enforcement: never send the shard + Bearer token in cleartext --
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"shard upload requires HTTPS, got {parsed.scheme!r} — "
            f"refusing to send shard over plaintext")
    # --- hostname pin: HARD-FAIL on an unexpected host ------------------------
    # A shard uploaded to the wrong host never reaches the real gate, so the
    # packed binary is keyed to a shard the server can never release -> a
    # permanent brick. Refuse rather than warn, unless explicitly allowed.
    if _SHARD_API_HOST and parsed.hostname != _SHARD_API_HOST:
        if not allow_unpinned_host:
            raise ValueError(
                f"shard upload host {parsed.hostname!r} does not match the pinned "
                f"{_SHARD_API_HOST!r}; refusing (a misrouted shard permanently "
                f"bricks the binary). Pass allow_unpinned_host / "
                f"--allow-unpinned-host to override for a staging host.")
        _emit(progress, f"WARNING: shard upload host {parsed.hostname!r} != "
                        f"pinned {_SHARD_API_HOST!r} (allowed by override)")

    endpoint = f"{parsed.scheme}://{parsed.netloc}/api/shard/store"
    body = json.dumps({
        "build_id": build_id,
        "license_id": license_id,
        "hwid_hash": hwid_hash,
        "shard": shard.hex(),
        "max_activations": int(max_activations),
        "ttl_hours": int(ttl_hours),
    }).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {auth}",
        },
        method="POST",
    )
    # Pin the CA chain instead of trusting the whole system store (anti-MITM).
    try:
        with _open_shard_request(
                req, timeout=15,
                context=_make_pinned_context(pin_pem)) as resp:
            status = resp.status
            payload = resp.read(_MAX_SHARD_RESPONSE + 1)
            if len(payload) > _MAX_SHARD_RESPONSE:
                raise RuntimeError("shard upload response exceeds 64 KiB")
    except urllib.error.HTTPError as e:
        # The v2 server returns {"error": "..."} with a 4xx/5xx on failure.
        error_body = e.read(_MAX_SHARD_RESPONSE + 1)
        if len(error_body) > _MAX_SHARD_RESPONSE:
            error_detail = "error response exceeds 64 KiB"
        else:
            error_detail = _extract_error(error_body)
        raise RuntimeError(
            f"shard upload rejected: HTTP {e.code} "
            f"({error_detail})") from None

    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        data = {}
    if status not in (200, 201) or not data.get("ok"):
        raise RuntimeError(
            f"shard upload failed: HTTP {status} "
            f"({data.get('error', 'unexpected response')})")
    returned_build_id = str(data.get("build_id", "")).strip().lower()
    if returned_build_id != build_id:
        raise RuntimeError(
            "shard upload returned a mismatched build_id; refusing to publish "
            "an artifact whose shard cannot be retrieved")
    return data


def _default_output_path(input_path: str) -> str:
    root, ext = os.path.splitext(input_path)
    return f"{root}.packed{ext}"


def _same_file_or_path(left: str, right: str) -> bool:
    """Return whether two paths identify the same file or canonical location."""
    try:
        if os.path.samefile(left, right):
            return True
    except (OSError, ValueError):
        pass
    canonical_left = os.path.normcase(os.path.realpath(os.path.abspath(left)))
    canonical_right = os.path.normcase(os.path.realpath(os.path.abspath(right)))
    return canonical_left == canonical_right


def detect_is_dll(input_path: str) -> bool:
    """Auto-detect EXE vs DLL straight from the COFF Characteristics field."""
    with open(input_path, "rb") as f:
        f.seek(0x3C)
        (e_lfanew,) = struct.unpack("<I", f.read(4))
        f.seek(e_lfanew)
        if f.read(4) != b"PE\x00\x00":
            raise ValueError(f"{input_path} is not a valid PE (no PE signature)")
        f.seek(e_lfanew + 4 + 18)        # file header + offset of Characteristics
        (characteristics,) = struct.unpack("<H", f.read(2))
    return bool(characteristics & _IMAGE_FILE_DLL)


def pack_file(input_path: str, options: PackOptions,
              progress: ProgressFn = None) -> PackResult:
    """Pack one PE. Returns a :class:`PackResult`; never raises past this boundary.

    ``perf_counter`` (monotonic) is used *only* for the elapsed measurement, so
    the timing never depends on wall-clock adjustments.
    """
    start = time.perf_counter()
    output_path: Optional[str] = None
    original_size = 0
    packed_size = 0
    build_id: Optional[str] = None
    stage_path: Optional[str] = None

    def _elapsed_ms() -> float:
        return (time.perf_counter() - start) * 1000.0

    try:
        # --- input validation ------------------------------------------------
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"input not found: {input_path}")
        original_size = os.path.getsize(input_path)

        # --- shard config sanity (fail loud BEFORE we key anything) ----------
        # assemble.py XORs the server shard into the key whenever server_shard
        # is True. If we then have no URL + auth to upload that shard, the
        # packed binary is keyed to a shard that never reaches the server and is
        # permanently unrunnable -- with no error. Refuse up front.
        if getattr(options, "server_shard", False):
            _shard_url = getattr(options, "shard_url", None)
            _shard_auth = getattr(options, "shard_auth", None)
            if not _shard_url or not _shard_auth:
                raise ValueError(
                    "server_shard=True requires both shard_url and shard_auth — "
                    "without them, the packed binary would be permanently "
                    "unrunnable (keyed to a shard that was never uploaded)")
            # v2 shard gate binds each build to a license + a target machine's
            # HWID hash at upload time; both are mandatory for a usable build.
            _license_id = getattr(options, "shard_license_id", None)
            _hwid_hash = getattr(options, "shard_hwid_hash", None)
            if not _license_id or not _hwid_hash:
                raise ValueError(
                    "server_shard=True requires shard_license_id and "
                    "shard_hwid_hash — the v2 shard gate binds each build to a "
                    "license and a target machine's HWID hash at upload time")
            _hh = _hwid_hash.strip().lower()
            if len(_hh) != 64 or any(c not in "0123456789abcdef" for c in _hh):
                raise ValueError(
                    "shard_hwid_hash must be a SHA-256 hex digest (64 hex chars)")

        # --- lazy imports of the sibling builder modules --------------------
        # Imported here (not at module load) so the front-ends can import the
        # orchestrator even while the parallel modules are still landing, and so
        # a missing dependency surfaces as a clean PackResult error.
        try:
            from . import pe_analyze, payload, assemble
        except ImportError:                              # flat / frozen layout
            import pe_analyze          # type: ignore
            import payload             # type: ignore
            import assemble            # type: ignore

        # --- resolve output + is_dll ----------------------------------------
        output_path = options.output_path or _default_output_path(input_path)
        if _same_file_or_path(input_path, output_path):
            raise ValueError(
                "input and output resolve to the same file; refusing to overwrite "
                "the source binary")
        is_dll = options.is_dll
        if is_dll is None:
            _emit(progress, "detecting PE type")
            is_dll = detect_is_dll(input_path)
        eff = replace(options, is_dll=is_dll, output_path=output_path)

        out_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(out_dir, exist_ok=True)

        # --- 1. analyze ------------------------------------------------------
        _emit(progress, f"analyzing {os.path.basename(input_path)} "
                        f"({'DLL' if is_dll else 'EXE'})")
        # pe_analyze's public entry is analyze_pe(); tolerate an analyze() alias.
        _analyze = getattr(pe_analyze, "analyze_pe", None) or \
            getattr(pe_analyze, "analyze")
        parsed = _analyze(input_path)

        # --- 2. build payload (compress + encrypt + serialize metadata) ------
        _emit(progress, "building payload (compress + AES-256-GCM)")
        artifacts = payload.build_payload(parsed, eff)

        # --- 3. assemble the output PE (graft stub, patch PackInfo, write) ---
        # Always assemble into a unique sibling staging file. This preserves any
        # existing output until every local check and optional shard upload has
        # succeeded, and prevents concurrent packs from sharing a .pending path.
        _emit(progress, "assembling packed PE (grafting stub)")
        stage_fd, stage_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(output_path)}.",
            suffix=".pending",
            dir=out_dir,
        )
        os.close(stage_fd)
        asm_result = assemble.build_output_pe(
            parsed, artifacts, stage_path, input_path=input_path, options=eff,
            stub_path=eff.stub_path)

        # The shard gate and bootstrap use the same signing-stable PE content
        # ID. Compute it only after the complete artifact exists but before a
        # server shard is stored. Authenticode signing later preserves this ID.
        build_id = _pe_content_id(stage_path)

        # --- 3b. upload server shard if one was generated --------------------
        if asm_result.server_shard and eff.shard_url and eff.shard_auth:
            _emit(progress, "uploading server shard (v2 shard gate)")
            try:
                _upload_shard(asm_result.server_shard,
                              build_id=build_id,
                              url=eff.shard_url, auth=eff.shard_auth,
                              license_id=eff.shard_license_id or "",
                              hwid_hash=eff.shard_hwid_hash or "",
                              max_activations=eff.shard_max_activations,
                              ttl_hours=eff.shard_ttl_hours,
                              allow_unpinned_host=getattr(eff, "allow_unpinned_host", False),
                              pin_pem=(eff.shard_pin_pem
                                       or os.environ.get("LETHE_SHARD_PIN_PEM")),
                              progress=progress)
            except Exception:
                # The staged binary is keyed to a shard that never reached the
                # server. The function-wide finally block removes it.
                _emit(progress, "shard upload failed; removing staged output")
                raise

        # Size and all fallible validation happen before publication. os.replace
        # is atomic within this directory/filesystem.
        packed_size = os.path.getsize(stage_path)
        os.replace(stage_path, output_path)
        stage_path = None
        asm_result.output_path = output_path

        # --- 4. results ------------------------------------------------------
        ratio = (packed_size / original_size) if original_size else 0.0
        _emit(progress, f"done: {packed_size:,} B "
                        f"({ratio * 100:.1f}% of original)")
        return PackResult(
            input_path=input_path, output_path=output_path, ok=True, error=None,
            original_size=original_size, packed_size=packed_size, ratio=ratio,
            elapsed_ms=_elapsed_ms(), build_id=build_id)

    except Exception as exc:                             # never raise past here
        detail = f"{type(exc).__name__}: {exc}"
        _emit(progress, f"FAILED: {detail}")
        # keep a compact traceback tail in the error for post-mortem in logs
        tb = traceback.format_exc(limit=4).strip().splitlines()
        error = detail if len(tb) <= 1 else detail + "\n" + "\n".join(tb[-6:])
        return PackResult(
            input_path=input_path, output_path=output_path, ok=False, error=error,
            original_size=original_size, packed_size=packed_size,
            ratio=0.0, elapsed_ms=_elapsed_ms(), build_id=build_id)
    finally:
        if stage_path is not None:
            try:
                os.remove(stage_path)
            except OSError:
                pass
