# FeltCrypto

[![CI](https://github.com/PrincetonAfeez/Encryption-Algorithm/actions/workflows/ci.yml/badge.svg)](https://github.com/PrincetonAfeez/Encryption-Algorithm/actions/workflows/ci.yml)

**Author:** Princeton Afeez · **Capstone:** Systems Programming in Python

FeltCrypto is an academic Python library for learning why “don’t roll your own
crypto” is practical advice. It builds deliberately weak local constructions,
breaks those constructions against bundled toy fixtures, explains the failed
invariant, and ends with a small AES-GCM API backed by `cryptography`.

> **Portfolio pitch:** I built a Python teaching library that breaks naive
> ciphers and demonstrates classic crypto pitfalls — to internalize why we use
> audited libraries.

See [CHANGELOG.md](CHANGELOG.md) for release history and
[docs/adr/0001-local-fixtures-and-narrow-safe-api.md](docs/adr/0001-local-fixtures-and-narrow-safe-api.md)
for the academic safety boundary and narrow safe API design.

> **Educational use only.** Weak modules are under `feltcrypto.weak`, are
> explicitly not secure, and operate only on bundled or locally generated
> fixtures. This project does not scan networks, probe services, guess
> credentials, recover third-party data, or accept arbitrary attack targets.

## Install and run

Python 3.11 or newer is required.

**Editable install (recommended for development):**

```console
python -m pip install -e ".[dev]"
```

**Requirements files** (pinned lockfiles generated with `pip-compile`):

```console
python -m pip install --require-hashes -r requirements.txt       # runtime only
python -m pip install --require-hashes -r requirements-dev.txt   # dev/CI tools
python -m pip install -e . --no-deps                             # local package
```

To regenerate lockfiles after changing `requirements.in` or `requirements-dev.in`:

```console
python -m pip install pip-tools
pip-compile --generate-hashes --output-file=requirements.txt requirements.in
pip-compile --generate-hashes --output-file=requirements-dev.txt requirements-dev.in
```

```console
python -m feltcrypto --version
python -m feltcrypto list
python -m feltcrypto show padding-oracle-demo
python -m feltcrypto padding-oracle-demo
python -m feltcrypto do-it-right --json
pytest
```

On Windows the `feltcrypto` script may not be on PATH; use `python -m feltcrypto`
for every command above.

The direct lesson commands are aliases for `feltcrypto run LESSON_ID` (see
`feltcrypto --help`). Use `feltcrypto run-all` to execute the full learning arc;
text output ends with a success summary. Every **weak** lesson command prints a
safety notice. JSON results for weak lessons contain:

```json
{
  "educational_only": true,
  "local_fixture": true,
  "not_for_real_use": true
}
```

The safe resolution lesson (`do-it-right`) sets `"not_for_real_use": false` because
it demonstrates the vetted API, not an attack.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | The command succeeded (`list`/`show`, or a lesson whose demo succeeded). |
| `1` | A lesson ran but its demo did not succeed (`run` / `run-all`). |
| `2` | Argparse usage error (invalid flags, missing arguments, unknown subcommand). |
| `3` | Handled runtime or domain error (for example, an unknown lesson id via `show` or `run`). |

Usage errors are raised by `argparse` before any lesson runs. Runtime errors from
the registry or lesson demos use exit code `3` so scripts can tell malformed
invocations apart from valid commands that failed during execution.

Only a **registered** lesson id may be used as a direct alias
(`feltcrypto break-caesar` → `feltcrypto run break-caesar`). A mistyped
subcommand such as `feltcrypto lst` is an unknown subcommand and exits with
code `2`, not an unknown-lesson runtime error.

## Bytes first

Cryptography operates on **bytes**. Hex and Base64 are reversible text
encodings, not encryption. `feltcrypto.foundations` provides strict hex/Base64
parsers, XOR, Hamming distance, block splitting, transposition, histograms,
English scoring, and strictly validated PKCS#7 padding.

Malformed encodings and padding raise clear exceptions. Nothing silently
coerces invalid data.

**Input size:** parser helpers operate on in-memory strings and bytes. FeltCrypto
does not enforce an application-level size limit because the library only accepts
local educational inputs (bundled fixtures and small API examples). Very large
inputs are bounded only by available memory; tests verify that reasonably large
hex and Base64 values still parse correctly.

These parsers (`parse_bytes` for text, hex, and Base64) are part of the top-level
`feltcrypto` API, alongside `feltcrypto.safe_api` helpers such as `generate_key`,
`encrypt`, and `decrypt`. The CLI itself exposes no arbitrary-input path by design: every demo runs
against a bundled fixture or a locally generated toy value, so there is no
command that breaks user-supplied ciphertext.

## Lesson map

| Lesson | Weak assumption and observation | Correct construction | SAFE API LINK |
|---|---|---|---|
| `break-caesar` | Brute force plus frequency analysis recover the shift. | AEAD | `feltcrypto.safe_api.encrypt/decrypt` |
| `break-substitution` | Word shapes and frequencies survive substitution. | AEAD | `feltcrypto.safe_api.encrypt/decrypt` |
| `break-vigenere` | A repeated key creates periodic Caesar columns. | AEAD with secure keys/nonces | `feltcrypto.safe_api.encrypt/decrypt` |
| `break-single-byte-xor` | A 256-value keyspace is exhaustive-search size. | AEAD with a generated key | `feltcrypto.safe_api.generate_key/encrypt/decrypt` |
| `break-repeating-xor` | Hamming distance reveals the key period. | Never construct repeating keystreams | `feltcrypto.safe_api.encrypt/decrypt` |
| `two-time-pad` | Unique pad round-trips; reuse cancels the pad. | Unique nonces and managed keys | `feltcrypto.safe_api.generate_key/encrypt/decrypt` |
| `detect-ecb` | Equal blocks produce equal ciphertext blocks. | AES-GCM or another vetted AEAD | `feltcrypto.safe_api.encrypt/decrypt` |
| `cbc-bit-flip` | CBC ciphertext is predictably malleable without a MAC. | AEAD | `feltcrypto.safe_api.encrypt/decrypt` |
| `padding-oracle-demo` | One padding-validity bit recovers complete plaintext. | Authenticate before releasing plaintext | `feltcrypto.safe_api.encrypt/decrypt` |
| `nonce-reuse` | CTR nonce reuse repeats the keystream. | Internal fresh-nonce generation | `feltcrypto.safe_api.encrypt (fresh nonce each call)` |
| `length-extension-demo` | `SHA1(key \|\| message)` exposes resumable hash state. | HMAC or AEAD | `feltcrypto.safe_api.encrypt/decrypt or HMAC-SHA256` |
| `timing-attack-demo` | Early-return comparison leaks prefix agreement through time. | Constant-time comparison | `hmac.compare_digest` |
| `predict-time-seed` | A timestamp seed has a tiny search window. | CSPRNG key generation | `feltcrypto.safe_api.generate_key` |
| `predict-mt19937` | 624 outputs clone Python's simulation PRNG. | CSPRNG key generation | `feltcrypto.safe_api.generate_key` |
| `do-it-right` | Tampering is rejected; all 14 prior failures map to one safe API. | AES-GCM safe API | `feltcrypto.safe_api.generate_key/encrypt/decrypt` |

## Development and quality gates

Install dev dependencies (`pip install -e ".[dev]"` or the pinned
`requirements-dev.txt` workflow above), then run the same checks as CI:

```console
python -m pip install -e ".[dev]"
```

| Task | Command |
|---|---|
| Full local check (matches CI) | `make check` (Git Bash / WSL) or run the rows below |
| Lint | `ruff check .` |
| Format | `ruff format .` |
| Typecheck | `mypy` |
| Tests + coverage | `pytest --cov=feltcrypto --cov-report=term-missing --cov-fail-under=99` |
| Property-based tests | `pytest tests/test_properties.py tests/test_properties_extended.py` |

CI runs these gates on Python 3.11–3.13 via GitHub Actions (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)). The suite currently
includes **181 tests** across **17 modules** with a **99%** line-coverage gate.

### Test layout

| Module | Focus |
|---|---|
| `test_foundations.py` | Hex/Base64, XOR, PKCS#7, scoring helpers |
| `test_safe_api.py` | AES-GCM round trip, tampering, package parsing |
| `test_classical_and_xor.py` | Lesson-level classical and XOR breaks |
| `test_classical_exhaustive.py` | Classical cipher edge cases and validation |
| `test_xor_exhaustive.py` | XOR/OTP/crib-drag edge cases |
| `test_block_modes.py` | ECB, CBC, padding oracle, CTR reuse |
| `test_integrity_and_randomness.py` | MAC, timing, RNG failure demos |
| `test_sha1_educational.py` | Educational SHA-1 and length extension |
| `test_registry_and_cli.py` | Lesson registry, CLI, resolutions sync |
| `test_cli_exhaustive.py` | CLI output helpers and exit codes |
| `test_errors_and_models.py` | Exception hierarchy and typed models |
| `test_fixtures.py` | Bundled fixture constants |
| `test_package_init.py` | Public exports and version metadata |
| `test_api_surface.py` | Import smoke tests for every submodule |
| `test_properties.py` | Hypothesis round-trip invariants |
| `test_properties_extended.py` | Hypothesis coverage for foundations helpers |
| `test_schema_documents.py` | JSON Schema files and documented output shapes |

On Windows without Make, invoke the commands in the table directly in PowerShell
or your terminal.

## Representative transcript

```console
> feltcrypto break-caesar
========================================================================
LESSON: break-caesar
SAFETY: Educational only: this demonstrates a known failure against intentionally vulnerable local fixture data. Do not use it on unauthorized systems or data.
FIXTURE: caesar-local (local=true)
SUCCESS: true
OBSERVATION: Brute force plus English scoring finds the plaintext; letter-frequency analysis picks the same shift.
DIAGNOSTICS: {"confidence_gap": ..., "frequency_guess": 11, "frequency_matches_brute_force": true, ...}
RECOVERED KEY: 11
RECOVERED PLAINTEXT: Looks scrambled is not security. Letter frequencies survive a shift cipher.
TAKEAWAY: A shifted alphabet retains language structure and offers no meaningful secrecy.
SAFE API: feltcrypto.safe_api.encrypt/decrypt
```

```console
> feltcrypto break-repeating-xor
========================================================================
LESSON: break-repeating-xor
SAFETY: Educational only: this demonstrates a known failure against intentionally vulnerable local fixture data. Do not use it on unauthorized systems or data.
FIXTURE: repeating-xor-local (local=true)
SUCCESS: true
OBSERVATION: Normalized Hamming distance suggests the period; transposed columns reduce to byte XOR.
RECOVERED KEY: ICE
RECOVERED PLAINTEXT: Cryptography is less about making text look mysterious and more about preserving carefully stated guarantees. [...output trimmed...]
TAKEAWAY: Repeating a short key exposes periodic structure and turns one problem into small ones.
SAFE API: feltcrypto.safe_api.encrypt/decrypt
```

```console
> feltcrypto two-time-pad
========================================================================
LESSON: two-time-pad
SAFETY: Educational only: ...
FIXTURE: two-time-pad-local (local=true)
SUCCESS: true
OBSERVATION: A unique pad round-trips with no cross-message leak; reusing that pad cancels the key.
DIAGNOSTICS: {"secure_baseline_plaintext": "meet me at the library at seven tonight.", ...}
MEASUREMENTS: {"crib_candidates": 5, "otp_unique_pad_roundtrip": true}
RECOVERED PLAINTEXT: send me the revised chapter at nine tonight.
TAKEAWAY: A one-time pad is secure only when random, message-length, secret, and never reused.
SAFE API: feltcrypto.safe_api.generate_key/encrypt/decrypt
```

```console
> feltcrypto padding-oracle-demo
========================================================================
LESSON: padding-oracle-demo
SAFETY: Educational only: this demonstrates a known failure against intentionally vulnerable local fixture data. Do not use it on unauthorized systems or data.
FIXTURE: padding-oracle-local (local=true)
SUCCESS: true
OBSERVATION: Only a valid/invalid padding bit was exposed, yet every plaintext byte was recovered.
RECOVERED PLAINTEXT: Padding oracles turn one leaked bit into recovered local plaintext.
DIAGNOSTICS: {"oracle_queries": 20485}
MEASUREMENTS: {"oracle_queries": 20485}
TAKEAWAY: Unauthenticated CBC plus distinguishable errors forms a decryption oracle; use AEAD.
SAFE API: feltcrypto.safe_api.encrypt/decrypt
```

```console
> feltcrypto timing-attack-demo
========================================================================
LESSON: timing-attack-demo
SAFETY: Educational only: ...
FIXTURE: timing-local (local=true)
SUCCESS: true
OBSERVATION: The early-return comparator spends much longer on a full prefix match.
DIAGNOSTICS: {"constant_time_api": "hmac.compare_digest", "python_timing_is_noisy": true}
MEASUREMENTS: {"full_match_median_ns": ..., "first_byte_mismatch_median_ns": ..., ...}
TAKEAWAY: Secrets can leak through runtime; compare tags with hmac.compare_digest.
SAFE API: hmac.compare_digest
```

```console
> feltcrypto do-it-right
========================================================================
LESSON: do-it-right
FIXTURE: safe-api-local (local=true)
SUCCESS: true
OBSERVATION: AES-GCM encrypts and authenticates; altered packages return no plaintext.
MEASUREMENTS: {"tampering_rejected": true}
RESOLUTIONS:
  - break-caesar: Classical shift cipher -> feltcrypto.safe_api.encrypt/decrypt
  - break-substitution: Simple substitution -> feltcrypto.safe_api.encrypt/decrypt
  - ... (12 more prior weak lessons in registry order) ...
TAKEAWAY: Use a vetted AEAD through a small API that owns nonce generation and verification.
SAFE API: feltcrypto.safe_api.generate_key/encrypt/decrypt
```

Timing figures vary by machine because Python and operating-system scheduling
are noisy. The demo uses repeated trials and reports medians rather than
pretending one measurement is definitive.

## The safe API

`feltcrypto.safe_api` intentionally exposes only:

- `generate_key()`
- `encrypt()`
- `decrypt()`
- `encode_package()`
- `decode_package()`

It uses AES-256-GCM from the audited `cryptography` package, generates a fresh
nonce internally, authenticates associated data, and raises
`AuthenticationError` after any ciphertext, nonce, tag, associated-data, or key
change. Authentication failure returns no plaintext.

```python
import feltcrypto
from feltcrypto import (
    AuthenticationError,
    decode_package,
    decrypt,
    encode_package,
    encrypt,
    generate_key,
    parse_bytes,
)

key = generate_key()
package = encrypt(key, b"local secret", associated_data=b"record=7")
assert decrypt(key, package) == b"local secret"
assert decrypt(key, decode_package(encode_package(package))) == b"local secret"
assert parse_bytes("6869", "hex") == b"hi"
```

`AuthenticationError`, `ParseError`, `PaddingError`, and `UnknownLessonError` are
re-exported from the top-level `feltcrypto` package. Alternatively, import from submodules:

```python
from feltcrypto.errors import AuthenticationError, ParseError
from feltcrypto.foundations import parse_bytes
from feltcrypto.safe_api import decode_package, decrypt, encode_package, encrypt, generate_key
```

Production applications still need a real key-management design. This capstone
does not turn its teaching code into production cryptography.

### Encrypted package format

`encode_package()` emits a compact JSON object. `decode_package()` validates the
document before returning an `EncryptedPackage`. Unknown JSON fields are ignored
during decode; authentication is verified only when `decrypt()` runs.

Example:

```json
{
  "algorithm": "AES-256-GCM",
  "associated_data": "",
  "ciphertext": "...",
  "nonce": "...",
  "version": 1
}
```

| Field | Type | Rules |
|---|---|---|
| `version` | integer | Must be `1`. Other values raise `ParseError`. |
| `algorithm` | string | Must be exactly `AES-256-GCM`. |
| `nonce` | string | Valid standard Base64; must decode to **12 bytes**. |
| `ciphertext` | string | Valid standard Base64; holds ciphertext **and** GCM tag. |
| `associated_data` | string | Valid standard Base64; may encode an empty byte string. |

Additional rules:

- The document must be a JSON object. Arrays and scalars are rejected.
- Malformed JSON or invalid Base64 raises `ParseError`.
- Missing required fields raise `ParseError`.
- After decoding, `decrypt()` verifies the AEAD tag. Any tampering, wrong key,
  or wrong associated data raises `AuthenticationError` and returns **no**
  plaintext.
- Future package formats must bump `version`; consumers should reject unknown
  versions rather than guessing compatibility.

Formal JSON Schemas:

- [Schema/encrypted-package.schema.json](Schema/encrypted-package.schema.json)
- [Schema/demo-result.schema.json](Schema/demo-result.schema.json)
- [Schema/lesson.schema.json](Schema/lesson.schema.json)

## Lesson contract

Every registry entry supplies:

1. the deliberately weak assumption;
2. a bundled deterministic fixture;
3. the observation or leak used by the attack;
4. a structured result with diagnostics and/or measurements when they add
   teaching value;
5. **FAILURE** — what broke;
6. **CAUSE** — which invariant failed;
7. **CORRECT CONSTRUCTION** — what belongs in a real design;
8. **SAFE API LINK** — the vetted replacement.

Run `feltcrypto show LESSON_ID` to read that four-part summary.

## What I learned

- “Looks random” is not a security property. Language and repeated structure
  survive classical substitutions and repeating keys.
- Perfect primitives do not rescue broken constructions. ECB leaks patterns;
  CBC is malleable; padding errors become oracles; repeated CTR nonces repeat
  keystreams.
- Confidentiality without integrity is an incomplete promise.
- MAC design and comparison behavior matter. HMAC avoids length extension, and
  constant-time comparison prevents runtime from becoming an output channel.
- Cryptographic randomness is its own requirement. Python’s `random` is good
  for simulations and wrong for keys.
- A deliberately boring, narrow AEAD API is a feature: it removes choices that
  callers should not have to make.

## Project structure

```text
src/feltcrypto/
  __init__.py          public exports: registry, safe_api, errors, foundations.parse_bytes
  __main__.py          python -m feltcrypto entry point
  cli.py               command-line interface and lesson dispatch
  errors.py            ParseError, PaddingError, AuthenticationError, ...
  foundations.py       strict byte and parsing helpers
  fixtures.py          bundled deterministic toy data
  models.py            typed lesson and result contracts
  registry.py          API/CLI lesson registry
  randomness.py        CSPRNG policy (secrets); isolated insecure demo RNGs
  safe_api.py          vetted AES-GCM resolution
  py.typed             PEP 561 marker (ships the type hints)
  weak/                visibly insecure teaching code (not top-level exported)
    block_modes.py     misused AES modes and padding oracle
    classical.py       Caesar, substitution, Vigenere
    integrity.py       naive MAC and timing leak demos
    randomness_failures.py  predictable RNG failures
    sha1.py            educational SHA-1 for length-extension demos
    xor.py             XOR and one-time-pad reuse
tests/
  test_properties.py          Hypothesis property-based foundation tests
  test_properties_extended.py   additional Hypothesis helpers coverage
  test_api_surface.py           import smoke tests for every submodule
  ...                           (17 modules total; 181 tests; 99% coverage gate)
requirements.in                 dependency constraints (runtime)
requirements-dev.in             dependency constraints (dev/CI)
requirements.txt                pinned runtime lockfile (pip-compile + hashes)
requirements-dev.txt            pinned dev/CI lockfile (pip-compile + hashes)
docs/adr/                       architecture decision records
Schema/                         JSON Schemas for CLI/API documents
CHANGELOG.md                    release history
LICENSE                         MIT
Makefile                        local lint/typecheck/test targets
.github/workflows/ci.yml        GitHub Actions quality gates
```

The package has no network requirement. Tests prove that attacks land only on
the intended local cases and that the safe construction fails closed.

