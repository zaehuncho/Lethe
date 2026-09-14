from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "stub" / "src" / "pe_loader.c"
CMAKE = ROOT / "stub" / "CMakeLists.txt"
NATIVE_TEST = ROOT / "stub" / "tests" / "forwarder_resolution_test.c"


def _resolver_source() -> str:
    source = LOADER.read_text(encoding="utf-8")
    start = source.index("static FARPROC resolve_forwarder(")
    end = source.index("#if defined(LETHE_FORWARDER_TEST_API)", start)
    return source[start:end]


def test_forwarder_resolution_delegates_only_after_bounded_validation() -> None:
    resolver = _resolver_source()
    assert "uint32_t fwd_size" in resolver
    assert "scan_limit = fwd_size < 512u ? fwd_size : 512u" in resolver
    assert "terminator == scan_limit" in resolver
    assert "func_len == 0u" in resolver
    assert "func[i] < '0' || func[i] > '9'" in resolver
    assert "parsed > (65535u - digit) / 10u" in resolver
    assert "parsed == 0u" in resolver
    assert resolver.index("if (!mod) return NULL") < resolver.index(
        "GetProcAddress((HMODULE)mod"
    )
    assert "resolve_export(mod" not in resolver


def test_forwarder_bound_is_derived_from_export_directory() -> None:
    source = LOADER.read_text(encoding="utf-8")
    call = source[source.index("/* Forwarder:") : source.index(
        "return (FARPROC)(base + func_rva);"
    )]
    assert "(uint64_t)export_rva + export_size" in call
    assert "- func_rva" in call
    assert "forwarder_bound, depth + 1" in call


def test_native_contract_covers_api_set_ordinal_and_negative_inputs() -> None:
    native = NATIVE_TEST.read_text(encoding="utf-8")
    cmake = CMAKE.read_text(encoding="utf-8")
    assert "api-set resolved:" in native
    assert '"kernel32.#%lu"' in native
    for malformed in (
        '"kernel32."',
        '".Sleep"',
        '"kernel32.#"',
        '"kernel32.#0"',
        '"kernel32.#65536"',
        '"kernel32.#1x"',
    ):
        assert malformed in native
    assert "LetheForwarderResolutionTest" in cmake
    assert "/W4 /WX /O2 /Gy" in cmake
    assert "add_test(NAME LetheForwarderResolution" in cmake


def test_pre_import_hardening_order_and_import_privacy_are_unchanged() -> None:
    source = LOADER.read_text(encoding="utf-8")
    run_start = source.index("int pe_loader_run(")
    run = source[run_start:]
    assert run.index("antidump_harden_early(cpi->is_dll)") < run.index(
        "resolve_imports(base"
    )

    resolver = _resolver_source()
    assert "protected-image import plaintext" in resolver
    assert "import_hash(func)" not in resolver
    assert "GetProcAddress((HMODULE)mod, func)" in resolver
