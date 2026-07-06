# Architecture Decision Record
## App — Encryption Algorithm
**Cryptography Education Systems Group | Document 1 of 5**
**Status: Accepted**

---

## Context

The Cryptography Education Systems group requires a portfolio-ready cryptography project that teaches why apparently plausible encryption constructions fail, without presenting weak cryptography as safe or providing an arbitrary attack tool.

The project is **FeltCrypto**, a local academic teaching library and CLI. It contains deliberately weak constructions under `feltcrypto.weak`, deterministic bundled fixtures, structured lessons that demonstrate each failure, and a small safe API backed by the audited `cryptography` package. The project is explicitly educational: it does not scan networks, probe services, recover third-party data, accept arbitrary attack targets, guess credentials, or claim that its teaching implementations are suitable for real protection.

The learning arc begins with byte encodings and classical ciphers, continues through XOR/key-reuse failures, block-mode misuse, integrity failures, side channels, and predictable randomness, and ends with an AES-256-GCM API that generates nonces internally and returns no plaintext after authentication failure.

---

## Decisions

### Decision 1 — Build a failure-mode teaching library, not a new cipher

**Chosen:** Demonstrate known cryptographic failures against bundled or locally generated toy fixtures, then map every failure to a vetted construction.

**Rejected:** Inventing a novel encryption algorithm or presenting hand-written cryptography as production-ready.

**Reason:** The strongest educational outcome is understanding broken invariants and learning when to use audited primitives. A novel cipher would encourage unsafe conclusions.

---

### Decision 2 — Keep weak code in an explicitly unsafe namespace

**Chosen:** Place vulnerable demonstrations under `feltcrypto.weak` and mark modules with “NOT SECURE. NEVER USE FOR REAL PROTECTION.”

**Rejected:** Mixing weak examples into the safe public API.

**Reason:** Namespace and documentation boundaries reduce the risk that teaching functions are mistaken for supported encryption helpers.

---

### Decision 3 — Restrict attacks to local fixtures

**Chosen:** The CLI runs only registered lessons backed by bundled or locally generated data.

**Rejected:** Accepting arbitrary ciphertext, remote hosts, user credentials, or third-party targets.

**Reason:** The project should teach cryptographic reasoning without becoming an operational attack utility.

---

### Decision 4 — Make bytes and strict parsing foundational

**Chosen:** Provide explicit text, hexadecimal, and Base64 parsing; XOR; Hamming distance; block splitting; transposition; histograms; English scoring; and strict PKCS#7 padding.

**Rejected:** Guessing encodings or silently coercing malformed values.

**Reason:** Cryptography operates on bytes. Clear representation boundaries prevent accidental ambiguity and make every lesson reproducible.

---

### Decision 5 — Use deterministic lesson fixtures

**Chosen:** Classical, XOR, block-mode, integrity, and randomness lessons use known local constants or locally generated values.

**Rejected:** Depending on internet services, live data, or nondeterministic targets.

**Reason:** Deterministic fixtures make lessons testable, reviewable, safe, and suitable for CI.

---

### Decision 6 — Use one typed lesson contract

**Chosen:** Every lesson has metadata, safety notice, weak assumption, explanation, a four-part summary, and a runner returning a structured `DemoResult`.

**Rejected:** Ad hoc print-only demonstrations.

**Reason:** A uniform contract allows the CLI and Python API to share the same registry and ensures every lesson states what failed, why it failed, the correct construction, and the safe API link.

---

### Decision 7 — Teach classical failures through exhaustive search and language structure

**Chosen:** Demonstrate Caesar brute force/frequency scoring, substitution word-pattern constraints, and Vigenère period recovery using Kasiski-style evidence and index of coincidence.

**Rejected:** Treating classical ciphers as meaningful modern protection.

**Reason:** These lessons show that visual scrambling does not remove language statistics or key-period structure.

---

### Decision 8 — Teach XOR failures through keyspace and reuse

**Chosen:** Demonstrate single-byte XOR exhaustive search, repeating-key XOR key-size recovery, and one-time-pad reuse.

**Rejected:** Presenting XOR as secure without strict key-generation and one-time-use requirements.

**Reason:** XOR is safe only inside a correct construction. Tiny keys and repeated keystreams expose strong algebraic relationships.

---

### Decision 9 — Use real AES primitives to demonstrate broken modes

**Chosen:** Use AES from `cryptography`, but deliberately misuse ECB, CBC without authentication, padding-oracle behavior, and CTR nonce reuse in local lessons.

**Rejected:** Implementing AES itself or implying that primitive strength rescues a broken mode/construction.

**Reason:** These lessons make an important distinction: a secure primitive can still be used insecurely.

---

### Decision 10 — Include integrity and side-channel failures

**Chosen:** Demonstrate a SHA-1 prefix-MAC length extension and an early-return comparison timing leak; contrast them with HMAC-SHA256 and `hmac.compare_digest`.

**Rejected:** Teaching encryption as the only cryptographic requirement.

**Reason:** Confidentiality without integrity is incomplete, and implementations can leak through observable behavior even when mathematical primitives are sound.

---

### Decision 11 — Separate secure randomness from simulation PRNGs

**Chosen:** Use `secrets.token_bytes` for secure bytes and keep time-seeded `random.Random` and MT19937 cloning inside explicitly named failure demonstrations.

**Rejected:** Using Python’s `random` module for encryption keys or nonces.

**Reason:** Statistical randomness is not unpredictability. Cryptographic keys require a CSPRNG.

---

### Decision 12 — Resolve the learning arc with a narrow AEAD API

**Chosen:** Expose only:
- `generate_key()`
- `encrypt()`
- `decrypt()`
- `encode_package()`
- `decode_package()`

**Rejected:** Exposing cipher mode selection, caller-provided nonces, padding choices, tag handling, or low-level AES controls.

**Reason:** A small API removes decisions that callers should not have to make and demonstrates secure-by-default design.

---

### Decision 13 — Use AES-256-GCM from `cryptography`

**Chosen:** Generate a 32-byte key, generate a fresh 12-byte nonce internally, authenticate associated data, and let AES-GCM return ciphertext with its tag.

**Rejected:** Custom AEAD, CBC+MAC composition, or manual tag formats.

**Reason:** AES-GCM is provided by an audited dependency and directly demonstrates authenticated encryption with associated data.

---

### Decision 14 — Fail closed on authentication errors

**Chosen:** Convert `InvalidTag` into `AuthenticationError` and return no plaintext.

**Rejected:** Returning partial plaintext, distinguishing detailed tamper causes, or treating tag failure as a warning.

**Reason:** Authentication must succeed before plaintext is released.

---

### Decision 15 — Version and label encoded encrypted packages

**Chosen:** Serialize packages as deterministic JSON containing version, algorithm, Base64 nonce, ciphertext, and associated data.

**Rejected:** Unversioned opaque blobs or unlabeled fields.

**Reason:** A versioned envelope is inspectable and parseable while the cryptographic security remains in AES-GCM.

---

### Decision 16 — Keep key management out of scope

**Chosen:** Demonstrate generated in-memory keys and encrypted packages.

**Rejected:** Claiming to solve secret storage, rotation, hardware protection, passphrase derivation, or organization-wide key management.

**Reason:** A correct encryption primitive does not automatically create a complete production key-management design.

---

## Consequences

**Positive:**
- Every weak construction is visibly separated from the safe API.
- The CLI cannot target arbitrary external data.
- Lessons are deterministic and testable.
- The project demonstrates both cryptographic and implementation failures.
- The safe API owns nonce generation and authentication behavior.
- Structured results support text and JSON output.
- Strict parsing avoids silent corruption or coercion.
- The final lesson maps all prior failures to secure replacements.

**Negative / Trade-offs:**
- The project is not a general cryptanalysis toolkit.
- Weak modules could still be misused if copied out of context.
- Timing measurements remain noisy in Python.
- The substitution and padding-oracle demos are intentionally fixture-sized.
- AES-GCM key storage/rotation is not addressed.
- JSON package encoding is convenient but not a complete application protocol.
- The safe API is intentionally limited and may not fit every production use case.

---

## Alternatives Not Explored

- New/custom block cipher.
- Production cryptanalysis tooling.
- Network scanning or service probing.
- Password cracking.
- Public-key encryption API.
- Envelope encryption/KMS integration.
- Password-based key derivation.
- File-streaming encryption.
- Key rotation/version registry.
- Hardware-backed key storage.
- Formal cryptographic proofs.
- Native constant-time implementations.

---

*Constitution reference: Article 1 (Python fundamentals and architectural thinking), Article 3.3 (scope discipline), Article 4 (quality proportional to scope), Article 5 (trade-off documentation), Article 6 (verification), and Article 7 (progressive complexity).*

---


# Technical Design Document
## App — Encryption Algorithm
**Cryptography Education Systems Group | Document 2 of 5**

---

## Overview

FeltCrypto is a CLI-first academic cryptography teaching library. It provides strict byte utilities, intentionally weak local constructions, deterministic failure demonstrations, a typed lesson registry, and a small AES-256-GCM safe API.

**Package:** `feltcrypto`  
**Console script:** `feltcrypto`  
**Python:** `>=3.11`  
**Runtime dependency:** `cryptography>=43`  
**Development tools:** pytest, pytest-cov, Hypothesis, mypy, Ruff  
**Coverage gate:** 99%

---

## System Context

```text
User / Reviewer
  │
  ▼
feltcrypto CLI or Python API
  │
  ├── Lesson registry
  │     ├── metadata and safety contract
  │     ├── deterministic fixtures
  │     ├── weak lesson runner
  │     └── structured DemoResult
  │
  ├── foundations
  │     ├── strict encodings
  │     ├── XOR/Hamming/chunks
  │     ├── PKCS#7
  │     └── scoring/statistics
  │
  ├── feltcrypto.weak
  │     ├── classical
  │     ├── xor
  │     ├── block_modes
  │     ├── integrity
  │     ├── randomness_failures
  │     └── educational SHA-1
  │
  └── safe_api
        ├── secrets.token_bytes
        ├── AES-256-GCM
        ├── authenticated package
        └── fail-closed decryption
```

---

## Package Areas

```text
src/feltcrypto/
  __init__.py          # top-level public exports
  __main__.py          # python -m feltcrypto
  cli.py               # list/show/run/run-all
  errors.py            # parse, padding, lesson, authentication errors
  foundations.py       # byte encodings, XOR, padding, scoring
  fixtures.py          # deterministic local lesson data
  models.py            # Lesson, LessonSummary, DemoResult
  randomness.py        # secure bytes and explicitly insecure demo RNG
  registry.py          # ordered lesson registry and runners
  safe_api.py          # AES-256-GCM API and package format
  weak/
    classical.py       # Caesar, substitution, Vigenère
    xor.py             # single/repeating XOR and OTP reuse
    block_modes.py     # ECB/CBC/CTR misuse demos
    integrity.py       # length extension and timing comparison
    randomness_failures.py
    sha1.py            # educational resumable SHA-1 implementation
```

---

## Core Typed Models

### `LessonSummary`

```python
@dataclass(frozen=True)
class LessonSummary:
    failure: str
    cause: str
    correct_construction: str
    safe_api_link: str
```

Every lesson must explain:
1. what failed;
2. which invariant failed;
3. the correct construction;
4. the safe API replacement.

### `DemoResult`

```python
@dataclass
class DemoResult:
    lesson_id: str
    concepts: tuple[str, ...]
    fixture_name: str
    success: bool
    observation: str
    takeaway: str
    safe_api_reference: str
    recovered_key: str | None
    recovered_plaintext: str | None
    measurements: dict[str, JSONValue]
    diagnostics: dict[str, JSONValue]
    educational_only: bool = True
    local_fixture: bool = True
    not_for_real_use: bool = True
```

The safe `do-it-right` lesson changes `not_for_real_use` to `False`; weak lessons retain all safety markers.

### `Lesson`

```python
@dataclass(frozen=True)
class Lesson:
    lesson_id: str
    title: str
    concepts: tuple[str, ...]
    fixture_name: str
    weak_assumption: str
    safety_notice: str
    summary: LessonSummary
    run_demo: Callable[[], DemoResult]
    explanation: str
    is_weak: bool = True
```

---

## Foundations Layer

### Encoding helpers

- `hex_encode` / `hex_decode`
- `base64_encode` / `base64_decode`
- `parse_bytes(value, representation)`

Representations are explicit:
- `text`
- `hex`
- `base64`

Malformed values raise `ParseError`.

### Byte operations

- fixed-length XOR
- Hamming distance
- block chunking
- block transposition
- byte histograms
- repeated-block counting

Length mismatches and invalid sizes raise clear exceptions.

### PKCS#7

`pkcs7_pad`:
- block size 1–255
- always appends padding
- aligned input gains a full padding block

`pkcs7_unpad`:
- input must be non-empty and aligned
- final byte defines padding length
- every padding byte must match
- malformed padding raises `PaddingError`

### Statistical helpers

- normalized English byte score
- index of coincidence
- repeated ciphertext-block count

These are explanatory heuristics, not cryptographic security tests.

---

## Classical Cipher Lessons

### Caesar

Flow:
1. encrypt with one of 26 shifts;
2. try every key;
3. score each plaintext;
4. compare with a frequency-derived shift guess.

Failure:
- tiny keyspace;
- letter frequencies survive.

### Simple substitution

Flow:
1. extract ciphertext words;
2. group local vocabulary by length and repetition pattern;
3. backtrack over consistent cipher/plain mappings;
4. rank resulting plaintexts.

Scope:
- intentionally small bundled phrase/vocabulary;
- not a general substitution cracking service.

### Vigenère

Flow:
1. strip letters;
2. gather Kasiski-style repeated-trigram distance votes;
3. test key lengths;
4. transpose into Caesar columns;
5. use chi-squared frequency fit for each shift;
6. rank plaintexts with English score and IoC structure.

Failure:
- repeated key creates periodic columns.

---

## XOR Lessons

### Single-byte XOR

- keyspace is exactly 256 values;
- every candidate is decrypted and scored;
- best English-looking plaintext wins.

### Repeating-key XOR

- rank key sizes by normalized Hamming distance;
- split into key-size blocks;
- transpose columns;
- solve each as single-byte XOR;
- reduce repeated key multiples to their shortest period.

### One-time-pad reuse

Correct baseline:
- random message-length pad used once round-trips.

Failure demonstration:
```text
C1 XOR C2 = P1 XOR P2
```

Known plaintext or crib dragging can reveal the counterpart message when the same pad is reused.

---

## Block-Mode Lessons

The AES primitive comes from `cryptography`; failures are in the construction.

### ECB pattern detection

- encrypt repeated aligned blocks with AES-ECB;
- detect identical ciphertext blocks;
- compare with CBC output.

### CBC bit flipping

- alter IV or preceding ciphertext block;
- cause a predictable XOR delta in the next plaintext block;
- demonstrate that confidentiality without authentication is malleable.

### Padding oracle

- local oracle returns only valid/invalid padding;
- attacker crafts the prior block byte by byte;
- intermediate state and plaintext are recovered;
- query count is reported.

### CTR nonce reuse

- encrypt two messages under the same key/nonce;
- repeated counter stream produces repeated keystream;
- known plaintext reveals the other message overlap.

---

## Integrity and Side-Channel Lessons

### Length extension

Broken construction:
```text
SHA1(key || message)
```

The public digest exposes resumable internal state. With a guessed key length, the lesson constructs glue padding, resumes hashing, appends a suffix, and produces a valid forged tag.

Safe contrast:
- HMAC-SHA256;
- original HMAC does not authenticate the extended message.

### Timing comparison

Broken comparator:
- returns at first mismatch;
- performs deterministic CPU work per matching byte.

Measurement:
- repeated trials;
- median first-byte mismatch time;
- median full-match time;
- ratio reported with an explicit warning that Python/OS timing is noisy.

Safe contrast:
- `hmac.compare_digest`.

---

## Randomness Lessons

### Time-seeded token

- seed a simulation PRNG with a timestamp;
- generate a 32-bit token;
- search a small timestamp window;
- recover the seed.

### MT19937 cloning

- observe 624 consecutive 32-bit outputs;
- reverse tempering operations;
- reconstruct CPython’s generator state;
- predict future outputs.

Safe policy:
- `secure_bytes()` calls `secrets.token_bytes`;
- insecure RNG helpers are explicitly named and isolated.

---

## Safe API

### Constants

```text
PACKAGE_VERSION = 1
KEY_SIZE = 32
NONCE_SIZE = 12
algorithm = AES-256-GCM
```

### `EncryptedPackage`

```python
@dataclass(frozen=True)
class EncryptedPackage:
    nonce: bytes
    ciphertext: bytes
    associated_data: bytes = b""
```

The `ciphertext` field contains the AES-GCM ciphertext and authentication tag returned by `cryptography`.

### Key generation

```python
def generate_key() -> bytes:
    return secrets.token_bytes(32)
```

### Encryption

```text
validate key length
create fresh 12-byte nonce internally
AESGCM(key).encrypt(nonce, plaintext, associated_data)
return EncryptedPackage
```

Callers cannot provide/reuse a nonce through the public function.

### Decryption

```text
validate key length
validate nonce length
AESGCM(key).decrypt(...)
return plaintext only after successful authentication
map InvalidTag -> AuthenticationError
```

No plaintext is returned on authentication failure.

### Package encoding

Deterministic JSON fields:

```json
{
  "algorithm": "AES-256-GCM",
  "associated_data": "<base64>",
  "ciphertext": "<base64>",
  "nonce": "<base64>",
  "version": 1
}
```

Parsing rejects:
- invalid JSON;
- non-object root;
- unsupported version;
- wrong algorithm;
- missing/non-text fields;
- invalid Base64;
- nonce not exactly 12 bytes.

---

## Lesson Registry

The ordered registry contains:

1. `break-caesar`
2. `break-substitution`
3. `break-vigenere`
4. `break-single-byte-xor`
5. `break-repeating-xor`
6. `two-time-pad`
7. `detect-ecb`
8. `cbc-bit-flip`
9. `padding-oracle-demo`
10. `nonce-reuse`
11. `length-extension-demo`
12. `timing-attack-demo`
13. `predict-time-seed`
14. `predict-mt19937`
15. `do-it-right`

The final lesson dynamically builds a failure-to-safe-API map from prior weak lessons in registry order.

---

## Error Hierarchy

- `FeltCryptoError`
- `ParseError`
- `PaddingError`
- `UnknownLessonError`
- `AuthenticationError`

Boundary behavior:
- malformed representation/package -> `ParseError`
- malformed PKCS#7 -> `PaddingError`
- unknown lesson -> `UnknownLessonError`
- AES-GCM tag/nonce/key mismatch -> `AuthenticationError` or key-length `ValueError`

---

## Known Limits

- Educational use only.
- Weak modules are intentionally insecure.
- No arbitrary attack input through the CLI.
- No network operations.
- No password cracking.
- No key storage or rotation system.
- No streaming file encryption.
- No public-key encryption.
- Python timing measurements are noisy.
- The substitution solver is fixture-oriented.
- The padding oracle is local and intentionally vulnerable.
- Safe API correctness does not solve application-level key management.

---

## Verification Summary

The repository configures:
- Python 3.11+
- `cryptography>=43`
- strict mypy
- Ruff lint and format checks
- pytest and Hypothesis
- coverage over `feltcrypto`
- 99% coverage floor
- CI across Python 3.11, 3.12, and 3.13

The documented test suite covers strict parsing, padding, property-based invariants, safe API round trips/tampering, classical/XOR attacks, block-mode failures, integrity/randomness demos, lesson registry/CLI behavior, public exports, and package metadata.

---

*Constitution reference: Article 4 (engineering quality), Article 6 (behavior verification), Article 7 (progressive complexity), and Article 8 (valid learner work).*

---


# Interface Design Specification
## App — Encryption Algorithm
**Cryptography Education Systems Group | Document 3 of 5**

---

## Public CLI Interface

### Console command

```powershell
feltcrypto <command> [options]
```

Equivalent module command:

```powershell
python -m feltcrypto <command> [options]
```

### Version

```powershell
feltcrypto --version
```

---

## Commands

### List lessons

```powershell
feltcrypto list
feltcrypto list --json
```

Text output labels each lesson as:
- `WEAK / EDUCATIONAL`
- `SAFE`

JSON output returns lesson metadata.

---

### Show lesson

```powershell
feltcrypto show break-caesar
feltcrypto show break-caesar --json
```

Text output includes:
- title and ID
- safety notice
- weak assumption
- explanation
- `FAILURE`
- `CAUSE`
- `CORRECT CONSTRUCTION`
- `SAFE API LINK`

---

### Run one lesson

```powershell
feltcrypto run break-caesar
feltcrypto run break-caesar --json
```

Direct aliases are accepted:

```powershell
feltcrypto break-caesar
feltcrypto padding-oracle-demo
feltcrypto do-it-right --json
```

A direct lesson ID is internally rewritten to `run <lesson-id>`.

---

### Run all lessons

```powershell
feltcrypto run-all
feltcrypto run-all --json
```

Text mode prints each structured result and ends with:

```text
SUMMARY: <successful>/<total> lessons succeeded
```

---

## Lesson IDs

```text
break-caesar
break-substitution
break-vigenere
break-single-byte-xor
break-repeating-xor
two-time-pad
detect-ecb
cbc-bit-flip
padding-oracle-demo
nonce-reuse
length-extension-demo
timing-attack-demo
predict-time-seed
predict-mt19937
do-it-right
```

---

## Text Result Contract

Weak lesson output contains:

```text
========================================================================
LESSON: <id>
SAFETY: <educational-only notice>
FIXTURE: <name> (local=true)
SUCCESS: true|false
OBSERVATION: <what happened>
RECOVERED KEY: <optional>
RECOVERED PLAINTEXT: <optional>
DIAGNOSTICS: <optional JSON>
MEASUREMENTS: <optional JSON>
TAKEAWAY: <lesson>
SAFE API: <replacement>
```

The safe lesson omits the weak safety line because it demonstrates the vetted API.

---

## JSON Result Contract

Every `DemoResult` includes:

```json
{
  "lesson_id": "break-caesar",
  "concepts": ["classical-cipher", "frequency-analysis"],
  "fixture_name": "caesar-local",
  "success": true,
  "observation": "...",
  "takeaway": "...",
  "safe_api_reference": "feltcrypto.safe_api.encrypt/decrypt",
  "recovered_key": "11",
  "recovered_plaintext": "...",
  "measurements": {},
  "diagnostics": {},
  "educational_only": true,
  "local_fixture": true,
  "not_for_real_use": true
}
```

`do-it-right` sets:

```json
"not_for_real_use": false
```

---

## CLI Safety Boundary

The CLI intentionally does **not** provide:
- arbitrary ciphertext input for breaking;
- remote host/port arguments;
- credential or password targets;
- file decryption attacks;
- network scanning;
- third-party target selection.

All weak commands run registered local fixtures.

---

## Safe Python API

### Generate a key

```python
from feltcrypto import generate_key

key = generate_key()
assert len(key) == 32
```

### Encrypt

```python
from feltcrypto import encrypt

package = encrypt(
    key,
    b"local secret",
    associated_data=b"record=7",
)
```

Contract:
- key must be exactly 32 bytes;
- nonce is generated internally;
- plaintext and associated data are bytes;
- result is `EncryptedPackage`.

### Decrypt

```python
from feltcrypto import decrypt

plaintext = decrypt(key, package)
```

Contract:
- verifies authentication before returning plaintext;
- wrong key or any package alteration raises `AuthenticationError`;
- no partial plaintext is returned.

### Encode/decode package

```python
from feltcrypto import encode_package, decode_package

serialized = encode_package(package)
restored = decode_package(serialized)
```

The serialized form is versioned deterministic JSON with Base64 fields.

### Parse bytes

```python
from feltcrypto import parse_bytes

parse_bytes("hello", "text")
parse_bytes("6869", "hex")
parse_bytes("aGk=", "base64")
```

No representation guessing occurs.

---

## Registry Python API

```python
from feltcrypto import (
    get_lesson,
    list_lessons,
    run_lesson,
    run_all_lessons,
)
```

- `list_lessons()` returns ordered lesson metadata.
- `get_lesson(id)` returns a `Lesson` or raises `UnknownLessonError`.
- `run_lesson(id)` returns `DemoResult`.
- `run_all_lessons()` runs the registry in order.

---

## Public Exports

Top-level exports include:
- `generate_key`
- `encrypt`
- `decrypt`
- `encode_package`
- `decode_package`
- `parse_bytes`
- registry helpers
- `Lesson`, `LessonSummary`, `DemoResult`
- `AuthenticationError`, `ParseError`, `PaddingError`, `UnknownLessonError`
- `foundations`
- `safe_api`

Weak functions remain under `feltcrypto.weak` and are not promoted as safe top-level helpers.

---

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Metadata command succeeded or lesson demo succeeded |
| `1` | A lesson executed but reported failure |
| `2` | Usage error or handled runtime error |

Handled runtime errors print through argparse’s error exit path.

---

## Side Effects

| Operation | Side Effect |
|---|---|
| list/show | Prints metadata only |
| run lesson | Performs local deterministic computation and prints result |
| timing lesson | Performs repeated CPU timing measurements |
| safe encryption | Generates random key/nonce bytes in memory |
| encode/decode package | Converts between object and JSON text |
| CLI | No network, filesystem-target attack, or credential side effects |

---

*Constitution reference: Article 4 (input/output boundaries), Article 6 (verification), and Article 8 (understandable and verifiable work).*

---


# Runbook
## App — Encryption Algorithm
**Cryptography Education Systems Group | Document 4 of 5**

---

## Requirements

### Runtime

- Python 3.11+
- `cryptography>=43`

### Development

- pytest
- pytest-cov
- Hypothesis
- mypy
- Ruff

---

## Installation

### Editable development install

```powershell
python -m pip install -e ".[dev]"
```

### Requirements-file install

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

On Windows, use `python -m feltcrypto` when the console script is not on PATH.

---

## First Smoke Test

```powershell
python -m feltcrypto --version
python -m feltcrypto list
python -m feltcrypto show break-caesar
python -m feltcrypto break-caesar
python -m feltcrypto do-it-right
```

Expected:
- package version prints;
- 15 lessons are listed;
- weak lesson prints the safety notice;
- Caesar fixture is recovered;
- safe lesson reports AES-GCM round trip and tampering rejection.

---

## Full Learning Arc

```powershell
python -m feltcrypto run-all
```

Expected:
- all registered lessons execute in order;
- each weak lesson identifies its broken invariant;
- final summary reports successful lessons;
- `do-it-right` maps all prior failures to safe APIs.

Machine-dependent note:
- timing figures vary;
- the lesson compares medians and reports raw measurements rather than claiming universal timing thresholds.

---

## JSON Demonstration

```powershell
python -m feltcrypto list --json
python -m feltcrypto show nonce-reuse --json
python -m feltcrypto run padding-oracle-demo --json
python -m feltcrypto do-it-right --json
```

Verify weak result markers:

```json
{
  "educational_only": true,
  "local_fixture": true,
  "not_for_real_use": true
}
```

Verify safe lesson:

```json
"not_for_real_use": false
```

---

## Safe API Smoke Test

```python
from feltcrypto import (
    AuthenticationError,
    decode_package,
    decrypt,
    encode_package,
    encrypt,
    generate_key,
)

key = generate_key()
package = encrypt(key, b"secret", associated_data=b"record=7")
assert decrypt(key, package) == b"secret"

encoded = encode_package(package)
assert decrypt(key, decode_package(encoded)) == b"secret"

altered = bytearray(package.ciphertext)
altered[0] ^= 1
try:
    decrypt(key, type(package)(package.nonce, bytes(altered), package.associated_data))
except AuthenticationError:
    pass
else:
    raise AssertionError("tampering was not rejected")
```

---

## Foundation Checks

```python
from feltcrypto.foundations import (
    base64_decode,
    fixed_xor,
    hamming_distance,
    pkcs7_pad,
    pkcs7_unpad,
)

assert base64_decode("aGk=") == b"hi"
assert fixed_xor(b"\x01\x02", b"\x03\x04") == b"\x02\x06"
assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37
assert pkcs7_unpad(pkcs7_pad(b"hello", 16), 16) == b"hello"
```

---

## Quality Gates

### Ruff lint

```powershell
ruff check .
```

### Ruff format check

```powershell
ruff format --check .
```

### Strict mypy

```powershell
mypy
```

### Tests and coverage

```powershell
pytest --cov=feltcrypto --cov-report=term-missing --cov-fail-under=99
```

### Property tests

```powershell
pytest tests/test_properties.py tests/test_properties_extended.py
```

---

## CI Parity

GitHub Actions runs on Python 3.11, 3.12, and 3.13:
- install requirements-dev
- editable package install
- Ruff lint
- Ruff format check
- strict mypy
- pytest with 99% coverage gate

---

## Troubleshooting

### Unknown lesson ID

Symptom:
```text
error: ...
```

Check:

```powershell
python -m feltcrypto list
```

Use the exact registered ID.

---

### `AuthenticationError`

Expected causes:
- ciphertext/tag changed;
- nonce changed;
- associated data changed;
- wrong key;
- malformed nonce length passed directly to `decrypt`.

Required behavior:
- do not use any plaintext;
- treat the package as unauthenticated.

---

### AES key length error

The safe API requires exactly 32 bytes.

Fix:

```python
key = generate_key()
```

Do not pad or truncate human passwords into keys. Password-based derivation is outside this project’s API.

---

### Package parse failure

Check:
- root is a JSON object;
- version is `1`;
- algorithm is `AES-256-GCM`;
- nonce/ciphertext/associated data are valid Base64 strings;
- nonce decodes to exactly 12 bytes.

---

### Timing lesson is noisy

Expected:
- Python process scheduling, CPU frequency, and background work affect measurements.

Actions:
- run on an otherwise idle machine;
- compare medians, not one timing sample;
- do not interpret the demonstration as a precision remote timing exploit.

---

### Padding-oracle lesson is slow

Expected:
- the fixture performs many oracle queries to recover each block byte.

The command is local-only and intentionally demonstrates why one leaked validation bit is dangerous.

---

### Weak module imported accidentally

Rule:
- do not use `feltcrypto.weak` for protection;
- use `feltcrypto.safe_api` or the top-level safe exports.

---

## Maintenance Notes

- Keep every weak module prominently marked unsafe.
- Keep the CLI fixture-only.
- Do not add arbitrary target or network arguments.
- Preserve the typed lesson contract.
- Preserve safety markers in JSON output.
- Keep nonce generation inside `encrypt()`.
- Never release plaintext before authentication succeeds.
- Add tests before changing package version/algorithm fields.
- Keep strict Base64/hex/padding parsing.
- Add an ADR before adding password derivation, key storage, file streaming, public-key encryption, or KMS integration.

---

*Constitution reference: Article 6 (behavior verification), Article 5 (constraints and trade-offs), and Article 8 (verifiable learner work).*

---


# Lessons Learned
## App — Encryption Algorithm
**Cryptography Education Systems Group | Document 5 of 5**

---

## Why This Design Was Chosen

This design was chosen because cryptography is easiest to misunderstand when code appears to work. Caesar, substitution, repeating XOR, ECB, CBC, and predictable PRNGs can all produce output that looks scrambled. The project therefore measures broken guarantees instead of judging visual appearance.

The most important architectural choice was separating weak demonstrations from the safe API. The weak code remains valuable because it exposes the exact invariant that failed, but the API that users should copy is intentionally small and backed by `cryptography`.

The second important choice was restricting the CLI to bundled/local fixtures. That keeps the capstone focused on learning and testing rather than creating a general attack tool.

The third important choice was the uniform lesson contract. Each lesson must move from assumption to observation to failure/cause to the correct construction. This prevents the project from becoming a collection of disconnected tricks.

---

## What Was Intentionally Omitted

**Novel encryption algorithm:** Explicitly rejected.

**Production cryptanalysis:** Out of scope.

**Network/service attacks:** Out of scope.

**Credential/password attacks:** Out of scope.

**Arbitrary attack inputs through CLI:** Omitted intentionally.

**Key management:** Deferred.

**Password-derived encryption:** Deferred.

**Public-key encryption/signatures:** Out of scope for the safe API.

**Streaming file encryption:** Deferred.

**Hardware/KMS integration:** Deferred.

**Formal proofs:** Out of scope.

---

## Biggest Weakness

The biggest weakness is that teaching code can be copied without its context. Strong naming, namespace separation, module warnings, CLI safety notices, and documentation reduce this risk, but cannot eliminate it.

The second weakness is that the safe API stops at primitive-level authenticated encryption. Real applications still need key storage, access control, rotation, backup, deletion, and incident response.

The third weakness is measurement fidelity. Python timing lessons demonstrate the direction of a side channel, not a production-grade remote timing exploit.

---

## Scaling Considerations

**If the curriculum grows:**
- add lessons only when each has a deterministic local fixture;
- preserve the four-part summary contract;
- map every weak lesson to a vetted replacement;
- keep runtime reasonable for `run-all`.

**If the safe API grows:**
- version package formats deliberately;
- add a streaming design rather than loading huge files into memory;
- define key identifiers and rotation semantics;
- avoid exposing nonce selection.

**If production use is considered:**
- move keys to an OS keyring, KMS, HSM, or dedicated secret store;
- define threat model and lifecycle;
- obtain security review;
- keep weak modules out of deployed artifacts.

---

## What the Next Refactor Would Be

1. **Separate teaching and safe distributions** — optionally publish weak lessons and safe API as distinct packages while retaining one repository.

2. **Versioned binary envelope option** — add an interoperable binary format without weakening the existing authenticated package.

3. **Streaming AEAD design** — define chunk authentication and truncation/reordering protection for large files.

4. **Key-management adapter interface** — let applications supply keys from a secure external provider without storing them in FeltCrypto.

5. **Lesson performance budget** — report expected runtime/query counts and keep full-course execution predictable.

---

## What This Project Taught

- **Scrambled is not secure.** Statistical and repeated structure survives weak constructions.

- **Primitive security and construction security are different.** AES used in ECB or unauthenticated CBC still fails important guarantees.

- **Key and nonce reuse are architectural failures.** Strong ciphers cannot repair repeated keystreams.

- **Confidentiality needs integrity.** Malleability and padding oracles disappear when authentication is enforced before plaintext release.

- **Hashing is not automatically a MAC.** HMAC’s construction matters.

- **Timing is an output channel.** Secret comparison behavior must be treated as part of the interface.

- **Simulation randomness is not key randomness.** MT19937 can be excellent for simulations and unacceptable for secrets.

- **Safe APIs should remove dangerous choices.** Internal nonce generation and fail-closed decryption are features.

- **Educational security tooling needs boundaries.** Fixture-only commands and explicit unsafe namespaces make the project more responsible and more defensible.

- **Using audited libraries remains necessary.** The capstone’s safe conclusion is not “the custom code is now secure”; it is “use vetted constructions through a narrow interface.”

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation), Article 6 (verification), and Article 7 (progressive complexity) for Encryption Algorithm.*
