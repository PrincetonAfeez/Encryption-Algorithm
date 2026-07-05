# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-06-19

### Added
- Expanded test suite to **160** cases across **16** test modules, including API
  surface smoke tests, Hypothesis property tests, and exhaustive weak-module
  edge cases.
- `requirements.txt` and `requirements-dev.txt` for runtime and CI/dev installs.
- Coverage gate raised to **99%** (`--cov-fail-under=99` and
  `[tool.coverage.report] fail_under`).

### Changed
- CI installs from `requirements-dev.txt`, enables pip caching, and uses workflow
  concurrency.
- README documents requirements-based install, test layout, and current quality
  gates.
- `.gitignore` explicitly excludes local academic scope planning documents.

## [0.1.3] - 2026-06-19

### Fixed
- `SAFE_API_RESOLUTIONS` is built from weak lessons in registry order (fixes
  `break-repeating-xor` / `two-time-pad` ordering).
- Resolution `prevention` and `safe_api_link` now match each lesson's
  `feltcrypto show` link.

### Changed
- Added diagnostics to `detect-ecb`, `cbc-bit-flip`, and `padding-oracle-demo`.
- Re-exported `AuthenticationError`, `ParseError`, `PaddingError`, and
  `UnknownLessonError` from top-level `feltcrypto`.
- Reduced redundant `do-it-right` / timing demo runs in tests via a shared fixture.
- `decode_package()` validates nonce length at parse time; CLI `run-all` prints a
  summary line and `--help` documents direct lesson aliases.

### Added
- Edge-case tests for safe API key length, package fields, block-mode validation,
  foundations helpers, and resolution-label registry sync.

### Documentation
- README: `python -m feltcrypto`, two-time-pad transcript, package serialization
  example, live CI badge URL template, softened diagnostics contract wording.

## [0.1.2] - 2026-06-19

### Fixed
- `do-it-right` resolution map now includes all **14** weak lessons (added
  `break-single-byte-xor`).
- Package version fallback matches `pyproject.toml` when metadata is unavailable.

### Changed
- `_summary()` default link uses the shared `AEAD_SAFE_API` constant.
- Registry test asserts every weak lesson appears in `SAFE_API_RESOLUTIONS`.

### Documentation
- README lesson map adds a SAFE API LINK column aligned with `feltcrypto show`.
- Added `do-it-right` and `timing-attack-demo` transcripts; placeholder repo URL note.

## [0.1.1] - 2026-06-19

### Changed
- Per-lesson `safe_api_link` values (for example `hmac.compare_digest` and
  `feltcrypto.safe_api.generate_key`) propagate into CLI and JSON output.
- `do-it-right` maps all prior weak lessons to safe API resolutions, printed
  in text mode as `RESOLUTIONS`.
- CLI text output now includes `DIAGNOSTICS` when a lesson provides them.
- Demo keys and messages for block modes, MAC, and safe API moved into
  `fixtures.py`.
- Top-level `feltcrypto` package re-exports documented public API symbols.
- `__version__` reads from installed package metadata (`pyproject.toml`).
- `make check` matches CI coverage gate; tests no longer run the full lesson
  arc twice.

### Documentation
- README portfolio framing, JSON safety exception for `do-it-right`, Caesar
  transcript, project structure, and dev workflow updates.

## [0.1.0] - 2026-06-19

Initial academic release: a teaching library that builds deliberately weak
cryptographic constructions, breaks them against bundled local fixtures, and
resolves into a small vetted AES-256-GCM API.

### Added
- Byte foundations: strict hex/Base64 parsing, fixed XOR, Hamming distance,
  block chunking/transposition, byte histograms, English scoring, index of
  coincidence, and strictly validated PKCS#7 padding.
- Classical lessons: Caesar, simple substitution, and Vigenere ciphers with
  brute-force, word-pattern, and Kasiski/IoC attacks.
- XOR lessons: single-byte and repeating-key XOR breaking, plus one-time-pad
  secure baseline and reuse (two-time pad) with crib dragging.
- Block-mode misuse: ECB detection, CBC bit-flipping, a CBC padding oracle, and
  CTR nonce reuse, all built over a vetted AES primitive.
- Integrity and side-channel lessons: SHA-1 length extension versus HMAC, and an
  early-return timing leak versus constant-time comparison.
- Randomness lessons: time-seeded key recovery and MT19937 state cloning,
  contrasted with a `secrets`-backed policy.
- `feltcrypto.safe_api`: AES-256-GCM with internal nonce generation, AEAD, and
  fail-closed verification.
- Typed lesson registry powering both the Python API and the `feltcrypto` CLI
  (`list`, `show`, `run`, `run-all`, with JSON output).

### Security
- Every weak module is namespaced under `feltcrypto.weak`, banners itself as
  not-for-real-use, and operates only on bundled local fixtures.

### Tooling
- Example-based and Hypothesis property-based `pytest` suites, `mypy --strict`,
  `ruff` lint + format gates, GitHub Actions CI across Python 3.11-3.13, and a
  `py.typed` marker so downstream code can consume the type hints.
