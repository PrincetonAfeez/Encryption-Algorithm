# FeltCrypto

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](.github/workflows/ci.yml)

> After publishing to GitHub, replace the CI badge URL with your repository's
> Actions badge, for example:
> `https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg`

> **Repository URLs:** `pyproject.toml` lists placeholder GitHub links
> (`PrincetonAfeez/feltcrypto`) for portfolio metadata. Update them after you
> create and push the remote, or reviewers may hit a 404.

**Author:** Princeton Afeez · **Capstone:** Systems Programming in Python

FeltCrypto is an academic Python library for learning why “don’t roll your own
crypto” is practical advice. It builds deliberately weak local constructions,
breaks those constructions against bundled toy fixtures, explains the failed
invariant, and ends with a small AES-GCM API backed by `cryptography`.

> **Portfolio pitch:** I built a Python teaching library that breaks naive
> ciphers and demonstrates classic crypto pitfalls — to internalize why we use
> audited libraries.

See [CHANGELOG.md](CHANGELOG.md) for release history.

> **Educational use only.** Weak modules are under `feltcrypto.weak`, are
> explicitly not secure, and operate only on bundled or locally generated
> fixtures. This project does not scan networks, probe services, guess
> credentials, recover third-party data, or accept arbitrary attack targets.

## Install and run

Python 3.11 or newer is required.

```console
python -m pip install -e ".[dev]"
feltcrypto --version
feltcrypto list
feltcrypto show padding-oracle-demo
feltcrypto padding-oracle-demo
feltcrypto do-it-right --json
pytest
```

The direct lesson commands are aliases for `feltcrypto run LESSON_ID`. Use
`feltcrypto run-all` to execute the full learning arc. Every **weak** lesson
command prints a safety notice. JSON results for weak lessons contain:

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
| `2` | A usage error or a handled runtime error (for example, an unknown lesson id). |

## Bytes first

Cryptography operates on **bytes**. Hex and Base64 are reversible text
encodings, not encryption. `feltcrypto.foundations` provides strict hex/Base64
parsers, XOR, Hamming distance, block splitting, transposition, histograms,
English scoring, and strictly validated PKCS#7 padding.

Malformed encodings and padding raise clear exceptions. Nothing silently
coerces invalid data.

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

Install dev dependencies, then run the same checks as CI:

```console
python -m pip install -e ".[dev]"
```

| Task | Command |
|---|---|
| Full local check (matches CI) | `make check` (Git Bash / WSL) or run the rows below |
| Lint | `ruff check .` |
| Format | `ruff format .` |
| Typecheck | `mypy` |
| Tests + coverage | `pytest --cov=feltcrypto --cov-report=term-missing --cov-fail-under=90` |
| Property-based tests | `pytest tests/test_properties.py` (Hypothesis) |

On Windows without Make, invoke the commands in the table directly in PowerShell
or your terminal. CI runs these gates on Python 3.11–3.13 via GitHub Actions.

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
> feltcrypto padding-oracle-demo
========================================================================
LESSON: padding-oracle-demo
SAFETY: Educational only: this demonstrates a known failure against intentionally vulnerable local fixture data. Do not use it on unauthorized systems or data.
FIXTURE: padding-oracle-local (local=true)
SUCCESS: true
OBSERVATION: Only a valid/invalid padding bit was exposed, yet every plaintext byte was recovered.
RECOVERED PLAINTEXT: Padding oracles turn one leaked bit into recovered local plaintext.
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
  - break-caesar: Classical shift cipher -> encrypt/decrypt AEAD instead of hand-built ciphers
  - break-substitution: Simple substitution -> encrypt/decrypt AEAD instead of alphabet permutations
  - ... (12 more prior weak lessons) ...
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
from feltcrypto import decrypt, encrypt, generate_key, parse_bytes

key = generate_key()
package = encrypt(key, b"local secret", associated_data=b"record=7")
assert decrypt(key, package) == b"local secret"
assert parse_bytes("6869", "hex") == b"hi"
```

Alternatively, import from submodules directly:

```python
from feltcrypto.foundations import parse_bytes
from feltcrypto.safe_api import decrypt, encrypt, generate_key
```

Production applications still need a real key-management design. This capstone
does not turn its teaching code into production cryptography.

## Lesson contract

Every registry entry supplies:

1. the deliberately weak assumption;
2. a bundled deterministic fixture;
3. the observation or leak used by the attack;
4. a structured result with diagnostics and measurements;
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
  __init__.py          public exports: registry, safe_api, foundations.parse_bytes
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
  test_properties.py   Hypothesis property-based foundation tests
  ...                  round trips, attacks, failure handling, CLI sync
CHANGELOG.md            release history
LICENSE                 MIT
Makefile                local lint/typecheck/test targets
.github/workflows/ci.yml GitHub Actions quality gates
```

The package has no network requirement. Tests prove that attacks land only on
the intended local cases and that the safe construction fails closed.

