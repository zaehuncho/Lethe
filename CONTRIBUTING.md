# Contributing to Lethe

Thank you for helping improve Lethe. Contributions should remain focused on
protecting and validating software that contributors own or are authorized to
test.

## Development setup

Use Python 3.12 and install the locked development environment:

```powershell
uv sync --frozen --group dev
```

Run the Python suites before opening a pull request:

```powershell
uv run pytest -q -p no:cacheprovider --ignore=tests/test_lifter.py
uv run pytest tests/test_lifter.py -q -p no:cacheprovider -p no:faulthandler
```

Native changes must also follow the clean-build and round-trip validation in
[`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md). Do not replace tracked
prebuilt binaries or generated opcode files unless the pull request explains
the provenance, exact build command, toolchain, and reproducibility checks.

To build the optional frozen GUI, install its locked dependency group and use
the same virtual-environment interpreter:

```powershell
uv sync --frozen --group gui-build
.\gui\build_gui.ps1 -PythonExe .\.venv\Scripts\python.exe
```

## Pull requests

- Keep each change focused and include tests for behavior changes.
- Describe security, compatibility, and release implications.
- Update documentation when commands or user-visible behavior change.
- Do not commit build outputs, credentials, private keys, certificates, or
  user-specific paths and data.
- Run the relevant checks and report any validation that could not be run.

Report security issues privately as described in [`SECURITY.md`](SECURITY.md),
not through a public pull request.

Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion are licensed under the Apache License 2.0 in accordance with the
repository's [`LICENSE`](LICENSE).
