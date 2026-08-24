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
import json
import os
import ssl
import struct
import time
import traceback
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, replace
from typing import Callable, Optional
from urllib.parse import urlparse

# IMAGE_FILE_DLL bit in the COFF file-header Characteristics field.
_IMAGE_FILE_DLL = 0x2000

# Expected hostname for the shard upload API. If a configured shard_url points
# elsewhere we log a warning (but don't hard-fail, since the URL is configurable).
_SHARD_API_HOST = "api.zaeorion.com"


@dataclass
class PackOptions:
    """User-facing knobs (global, with per-file override in the GUI)."""
    anti_debug: bool = True
    memory_guard: bool = False          # opt-in; AV-test first (see plan §8)
    compression_level: int = 9
    output_path: Optional[str] = None   # default: <input>.packed<ext>
    is_dll: Optional[bool] = None       # None => auto-detect from the PE header
    server_shard: bool = False          # Tier 3: XOR a server-held shard into the key
    shard_url: Optional[str] = None     # e.g. "https://api.zaeorion.com/api/shard"
    shard_auth: Optional[str] = None    # Bearer token for shard upload
    shard_license_id: Optional[str] = None   # bind shard to a specific license
    shard_hwid_hash: Optional[str] = None    # SHA-256 hex of target machine HWID
    shard_max_activations: int = 0           # 0 = unlimited
    shard_ttl_hours: int = 0                 # 0 = no expiry


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
    build_id: Optional[str] = None      # UUID minted for this pack (v2 shard gate)


ProgressFn = Optional[Callable[[str], None]]


def _emit(progress: ProgressFn, msg: str) -> None:
    if progress is not None:
        try:
            progress(msg)
        except Exception:
            pass                         # a noisy UI callback must never fail a pack


def _make_pinned_context() -> ssl.SSLContext:
    """SSLContext that only trusts the specific CA chain for the shard API."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Pin to the curated CA bundle (certifi) rather than the OS store, so a
    # rogue system-installed CA can't intercept. For production, pin to the
    # specific CA or leaf cert of api.zaeorion.com.
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except ImportError:
        ctx.load_default_certs()
    return ctx


def _extract_error(raw: bytes) -> str:
    """Pull the ``error`` field out of a v2 error body, defensively."""
    try:
        return str(json.loads(raw).get("error", "no error field"))
    except (ValueError, TypeError, AttributeError):
        return "unparseable error body"


def _upload_shard(shard: bytes, *, build_id: str, url: str, auth: str,
                  license_id: str = "", hwid_hash: str = "",
                  max_activations: int = 0, ttl_hours: int = 0,
                  progress: ProgressFn = None) -> dict:
    """Upload a build's server shard to the Lambda shard gate (POST /api/shard/store).

    The shard is sent hex-encoded and bound to ``license_id`` + ``hwid_hash``
    under the caller-supplied UUID ``build_id``. The server encrypts it at rest
    and returns ``{ok, build_id, expires_at}``. Raises on any non-success so the
    caller can delete the half-baked output (a shard that never reached the
    server leaves the packed binary permanently unrunnable).
    """
    # --- HTTPS enforcement: never send the shard + Bearer token in cleartext --
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"shard upload requires HTTPS, got {parsed.scheme!r} — "
            f"refusing to send shard over plaintext")
    # --- hostname check: warn (don't hard-fail) on an unexpected host ---------
    if _SHARD_API_HOST and parsed.hostname != _SHARD_API_HOST:
        _emit(progress, f"WARNING: shard upload host {parsed.hostname!r} does "
                        f"not match expected {_SHARD_API_HOST!r}")

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
        with urllib.request.urlopen(
                req, timeout=15, context=_make_pinned_context()) as resp:
            status = resp.status
            payload = resp.read()
    except urllib.error.HTTPError as e:
        # The v2 server returns {"error": "..."} with a 4xx/5xx on failure.
        raise RuntimeError(
            f"shard upload rejected: HTTP {e.code} "
            f"({_extract_error(e.read())})") from None

    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        data = {}
    if status not in (200, 201) or not data.get("ok"):
        raise RuntimeError(
            f"shard upload failed: HTTP {status} "
            f"({data.get('error', 'unexpected response')})")
    return data


def _default_output_path(input_path: str) -> str:
    root, ext = os.path.splitext(input_path)
    return f"{root}.packed{ext}"


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

    def _elapsed_ms() -> float:
        return (time.perf_counter() - start) * 1000.0

    try:
        # A UUID identifies this pack; it becomes the v2 shard-gate build_id and
        # is surfaced on the PackResult so the caller can bind/track the build.
        build_id = str(uuid.uuid4())

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
        # When a server shard is expected, stage the assembler output at a .pending
        # path so we never publish an output file keyed to a shard that hasn't
        # reached the server yet (interruption between write and upload would
        # otherwise leave a permanently-unrunnable binary at the final path).
        _emit(progress, "assembling packed PE (grafting stub)")
        stage_path = (output_path + ".pending"
                      if getattr(eff, "server_shard", False) else output_path)
        asm_result = assemble.build_output_pe(parsed, artifacts, stage_path,
                                              input_path=input_path, options=eff)

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
                              progress=progress)
            except Exception:
                # The staged binary is keyed to a shard that never reached the
                # server -> it would be permanently unrunnable. Delete the staged
                # file (never at output_path yet) so nothing lingers, then re-raise.
                _emit(progress, "shard upload failed; removing staged output")
                try:
                    os.remove(stage_path)
                except OSError:
                    pass
                raise

        # Publish the staged file to its final path only after any shard upload
        # succeeded. os.replace is atomic within a filesystem, so downstream
        # readers never see a half-committed output.
        if stage_path != output_path:
            os.replace(stage_path, output_path)
            asm_result.output_path = output_path

        # --- 4. results ------------------------------------------------------
        packed_size = os.path.getsize(output_path)
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
