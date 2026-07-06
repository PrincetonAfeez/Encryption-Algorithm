# ADR 0001: Local fixtures only and a narrow safe API

## Status

Accepted (2026-06-19)

## Context

FeltCrypto is an academic capstone library whose purpose is to make cryptographic
failure modes *felt*, not merely read about. That requires runnable attack demos,
but the topic is sensitive: historically weak crypto code has been misused as
offensive tooling.

The project must therefore teach attacks without becoming a general-purpose
breaker. Reviewers and contributors also need a clear boundary between
deliberately insecure teaching code and the vetted resolution path.

Several design choices follow from that constraint:

- Lessons operate on **bundled deterministic fixtures** or locally generated toy
  values, not user-supplied ciphertext from unknown systems.
- The **CLI** exposes lesson discovery and demo execution, not arbitrary
  hex/base64 attack inputs against third-party data.
- **Weak implementations** live under `feltcrypto.weak` with explicit
  not-for-real-use labeling.
- The **safe API** (`feltcrypto.safe_api`) is intentionally small: AES-256-GCM
  with internal nonce generation, package encoding, and fail-closed verification.

Callers are not given knobs for ECB/CBC mode selection, caller-supplied nonces,
unauthenticated encryption, or raw AES misuse—the patterns the lessons break.

## Decision

1. **Attack demos target local fixtures only.** Registry runners and CLI
   commands load named fixtures from `feltcrypto.fixtures` or generate bounded
   toy values inside the lesson. There is no CLI path to break arbitrary
   external ciphertext, files, tokens, or live services.

2. **Weak code is namespaced and labeled.** All insecure constructions import
   from `feltcrypto.weak.*`. Module docstrings and CLI output carry educational
   safety metadata (`educational_only`, `local_fixture`, `not_for_real_use`).

3. **The safe API is narrow by design.** Public production-oriented surface:

   - `generate_key()`
   - `encrypt()` / `decrypt()` (AES-256-GCM via `cryptography`)
   - `encode_package()` / `decode_package()`

   Nonce generation is **internal** to `encrypt()`. Authentication failures raise
   `AuthenticationError` and return no plaintext.

4. **Documentation and tests enforce the boundary.** README states the academic
   scope; tests assert registry/CLI sync, safety flags on weak lessons, and
   fail-closed behavior on tampered AEAD packages.

## Consequences

### Positive

- Portfolio reviewers can see an explicit safety posture without reading every
  module.
- Students interact with a consistent lesson arc: weak assumption → observable
  break → safe construction link.
- The safe API removes common footguns (nonce reuse, unauthenticated modes,
  caller-controlled mode assembly) that the weak lessons demonstrate.

### Negative

- The library cannot demonstrate breaks against arbitrary user ciphertext; that
  is intentional.
- Advanced readers cannot experiment with alternate AEAD libraries (for example
  PyNaCl) through the public safe API without extending the project.
- Maintainers must keep fixtures, registry entries, and CLI commands aligned so
  no lesson accidentally accepts unbounded external input.

## Alternatives considered

### Accept arbitrary CLI ciphertext inputs

Rejected. Would blur the line between education and a generic attack tool and
would complicate responsible-use messaging required for an academic capstone.

### Expose a full `cryptography` passthrough in the safe API

Rejected. Would reintroduce mode/nonce/MAC choices the lessons argue against.
Callers could repeat the same mistakes the curriculum breaks.

### Hide weak code entirely (safe API only)

Rejected. The pedagogical value depends on seeing weak constructions break.
Isolation under `feltcrypto.weak` plus labeling balances transparency and safety.

### Use libsodium/PyNaCl instead of AES-GCM for the resolution module

Deferred. AES-GCM via `cryptography` satisfies the capstone scope; switching
libraries would not change the fixture-only or narrow-API decisions above.
