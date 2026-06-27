# FeltCrypto

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](.github/workflows/ci.yml)

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
`feltcrypto run-all` to execute the full learning arc. Every attack command
prints a safety notice; JSON results contain:

```json
{
  "educational_only": true,
  "local_fixture": true,
  "not_for_real_use": true
}
```

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

These parsers (`parse_bytes` for text, hex, and Base64) are part of the library
API. The CLI itself exposes no arbitrary-input path by design: every demo runs
against a bundled fixture or a locally generated toy value, so there is no
command that breaks user-supplied ciphertext.

## Lesson map

| Lesson | Weak assumption and observation | Correct construction |
|---|---|---|
| `break-caesar` | A shifted alphabet looks scrambled; 26 keys are trivial to score. | AEAD |
| `break-substitution` | Word shapes and frequencies survive substitution. | AEAD |
| `break-vigenere` | A repeated key creates periodic Caesar columns. | AEAD with secure keys/nonces |
| `break-single-byte-xor` | A 256-value keyspace is exhaustive-search size. | AEAD |
| `break-repeating-xor` | Hamming distance reveals the key period. | Never construct repeating keystreams |
| `two-time-pad` | Unique pad round-trips; reuse cancels the pad and leaks the second message. | Unique nonces and managed keys |
| `detect-ecb` | Equal blocks produce equal ciphertext blocks. | AES-GCM or another vetted AEAD |
| `cbc-bit-flip` | CBC ciphertext is predictably malleable without a MAC. | AEAD |
| `padding-oracle-demo` | One padding-validity bit recovers complete plaintext. | Authenticate before releasing plaintext |
| `nonce-reuse` | CTR nonce reuse repeats the keystream. | Internal fresh-nonce generation |
| `length-extension-demo` | `SHA1(key || message)` exposes resumable hash state. | HMAC or AEAD |
| `timing-attack-demo` | Early-return comparison leaks prefix agreement through time. | `hmac.compare_digest` |
| `predict-time-seed` | A timestamp seed has a tiny search window. | `secrets` / `os.urandom` |
| `predict-mt19937` | 624 outputs clone Python’s simulation PRNG. | A CSPRNG |
| `do-it-right` | Tampering is rejected; prior failures map to one safe API. | The provided AES-GCM safe API |

## Development and quality gates

Install dev dependencies, then run the same checks as CI:

```console
python -m pip install -e ".[dev]"
```

| Task | Command |
|---|---|
| Full local check | `make check` (Git Bash / WSL) or run the rows below |
| Lint | `ruff check .` |
| Format | `ruff format .` |
| Typecheck | `mypy` |
| Tests + coverage | `pytest --cov=feltcrypto --cov-report=term-missing --cov-fail-under=90` |

On Windows without Make, invoke the commands in the table directly in PowerShell
or your terminal. CI runs these gates on Python 3.11–3.13 via GitHub Actions.

## Representative transcript

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
from feltcrypto.safe_api import decrypt, encrypt, generate_key

key = generate_key()
package = encrypt(key, b"local secret", associated_data=b"record=7")
assert decrypt(key, package) == b"local secret"
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
  cli.py               command-line interface and lesson dispatch
  foundations.py       strict byte and parsing helpers
  fixtures.py          bundled deterministic toy data
  models.py            typed lesson and result contracts
  registry.py          API/CLI lesson registry
  randomness.py        secure randomness policy
  safe_api.py          vetted AES-GCM resolution
  py.typed             PEP 561 marker (ships the type hints)
  weak/                visibly insecure teaching code
tests/                  round trips, attacks, failure handling, CLI sync
```

The package has no network requirement. Tests prove that attacks land only on
the intended local cases and that the safe construction fails closed.

