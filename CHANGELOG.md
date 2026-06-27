# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
