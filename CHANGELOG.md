# Changelog

All notable changes to Lethe are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-31

### Added

- Locked Python 3.12 development and optional GUI-build environments.
- Windows CI for Python tests, a clean native build, bootstrap compilation, and
  EXE/DLL regression round trips.
- Provenance manifests and explicit, acceptance-tested prebuilt promotion.
- Structural packed-output validation tied to live PE ranges.
- Apache-2.0 licensing, third-party notices, contribution guidance, and a
  private vulnerability-reporting policy.

### Changed

- The release-supported packing path is unmanaged x64 Windows EXEs.
- Anti-debug defaults to off; DLL, memory-guard, and remote-shard paths are
  explicitly experimental and are not release-approved.
- Output creation uses unique sibling staging and rejects source/output aliases.
- Shard uploads reject redirects and cap response sizes.
- Removed fake metadata, fake imports, fabricated strings, and fingerprint
  scrubbing intended to mislead inspection tools.

### Security

- Upgraded `cryptography` to 50.0.1.
- Hardened the experimental bootstrap against hash-to-execution replacement and
  centralized sensitive-buffer cleanup.

[0.1.0]: https://github.com/zaehuncho/Lethe/releases/tag/v0.1.0
