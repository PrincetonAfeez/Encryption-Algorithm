"""Typed lesson registry shared by the Python API and CLI."""

from __future__ import annotations

import dataclasses
import random
from collections.abc import Iterable
from typing import cast

from feltcrypto import fixtures, safe_api
from feltcrypto.errors import AuthenticationError, UnknownLessonError
from feltcrypto.foundations import byte_histogram, fixed_xor
from feltcrypto.models import DemoResult, DemoRunner, JSONValue, Lesson, LessonSummary
from feltcrypto.safe_api import EncryptedPackage
from feltcrypto.weak import block_modes, classical, integrity, randomness_failures, xor

SAFETY_NOTICE = (
    "Educational only: this demonstrates a known failure against intentionally "
    "vulnerable local fixture data. Do not use it on unauthorized systems or data."
)

DO_IT_RIGHT_SAFE_API = "feltcrypto.safe_api.generate_key/encrypt/decrypt"
AEAD_SAFE_API = "feltcrypto.safe_api.encrypt/decrypt"
GENERATE_KEY_API = "feltcrypto.safe_api.generate_key"
FRESH_NONCE_ENCRYPT = "feltcrypto.safe_api.encrypt (fresh nonce each call)"
AEAD_OR_HMAC = "feltcrypto.safe_api.encrypt/decrypt or HMAC-SHA256"
HMAC_COMPARE_DIGEST = "hmac.compare_digest"

_RESOLUTION_FAILURES: dict[str, str] = {
    "break-caesar": "Classical shift cipher",
    "break-substitution": "Simple substitution",
    "break-vigenere": "Repeating classical key",
    "break-single-byte-xor": "Tiny single-byte keyspace",
    "break-repeating-xor": "Repeating keystream",
    "two-time-pad": "One-time pad reuse",
    "detect-ecb": "ECB block patterns",
    "cbc-bit-flip": "Unauthenticated malleability",
    "padding-oracle-demo": "Padding oracle leakage",
    "nonce-reuse": "CTR nonce reuse",
    "length-extension-demo": "Naive hash(key || message) MAC",
    "timing-attack-demo": "Early-return secret comparison",
    "predict-time-seed": "Predictable key seed",
    "predict-mt19937": "Simulation PRNG for keys",
}


def _safe_api_resolutions_for(lessons: tuple[Lesson, ...]) -> tuple[dict[str, str], ...]:
    """Build the do-it-right map from weak lessons in registry order."""

    return tuple(
        {
            "prior_lesson": lesson.lesson_id,
            "failure": _RESOLUTION_FAILURES[lesson.lesson_id],
            "prevention": lesson.summary.safe_api_link,
            "safe_api_link": lesson.summary.safe_api_link,
        }
        for lesson in lessons
        if lesson.is_weak
    )


def _summary(
    failure: str,
    cause: str,
    correct: str,
    link: str = AEAD_SAFE_API,
) -> LessonSummary:
    return LessonSummary(failure, cause, correct, link)


def _result(
    lesson_id: str,
    concepts: tuple[str, ...],
    fixture_name: str,
    success: bool,
    observation: str,
    takeaway: str,
    *,
    recovered_key: str | None = None,
    recovered_plaintext: str | None = None,
    measurements: dict[str, JSONValue] | None = None,
    diagnostics: dict[str, JSONValue] | None = None,
) -> DemoResult:
    return DemoResult(
        lesson_id=lesson_id,
        concepts=concepts,
        fixture_name=fixture_name,
        success=success,
        observation=observation,
        takeaway=takeaway,
        safe_api_reference="",
        recovered_key=recovered_key,
        recovered_plaintext=recovered_plaintext,
        measurements=measurements or {},
        diagnostics=diagnostics or {},
    )


def _run_caesar() -> DemoResult:
    ciphertext = classical.caesar_encrypt(fixtures.CAESAR_PLAINTEXT, fixtures.CAESAR_KEY)
    candidates = classical.break_caesar(ciphertext)
    best = candidates[0]
    frequency_guess = classical.caesar_frequency_guess(ciphertext)
    frequency_matches = int(best.key) == frequency_guess
    return _result(
        "break-caesar",
        ("classical-cipher", "frequency-analysis", "brute-force"),
        "caesar-local",
        best.plaintext == fixtures.CAESAR_PLAINTEXT and frequency_matches,
        "Brute force plus English scoring finds the plaintext; "
        "letter-frequency analysis picks the same shift.",
        "A shifted alphabet retains language structure and offers no meaningful secrecy.",
        recovered_key=best.key,
        recovered_plaintext=best.plaintext,
        diagnostics={
            "frequency_guess": frequency_guess,
            "frequency_matches_brute_force": frequency_matches,
            "confidence_gap": classical.confidence_gap(candidates),
            "top_candidates": [{"key": item.key, "score": item.score} for item in candidates[:3]],
        },
    )


def _run_substitution() -> DemoResult:
    ciphertext = classical.substitution_encrypt(
        fixtures.SUBSTITUTION_PLAINTEXT, fixtures.SUBSTITUTION_ALPHABET
    )
    candidate = classical.break_substitution(ciphertext, fixtures.SUBSTITUTION_VOCABULARY)
    return _result(
        "break-substitution",
        ("classical-cipher", "frequency-analysis", "word-patterns"),
        "substitution-local",
        candidate.plaintext == fixtures.SUBSTITUTION_PLAINTEXT,
        "Repeated-letter shapes constrain each cipher word until a consistent mapping emerges.",
        "Substitution preserves word boundaries, repetition, and statistical language structure.",
        recovered_key=candidate.key,
        recovered_plaintext=candidate.plaintext,
        diagnostics={"score": candidate.score},
    )


def _run_vigenere() -> DemoResult:
    ciphertext = classical.vigenere_encrypt(fixtures.VIGENERE_PLAINTEXT, fixtures.VIGENERE_KEY)
    candidates = classical.break_vigenere(ciphertext)
    best = candidates[0]
    return _result(
        "break-vigenere",
        ("classical-cipher", "kasiski", "index-of-coincidence"),
        "vigenere-local",
        best.plaintext == fixtures.VIGENERE_PLAINTEXT,
        "Repeated-key columns behave like independent Caesar ciphers.",
        "A repeating key leaves periodic structure that reveals both key length and key letters.",
        recovered_key=best.key,
        recovered_plaintext=best.plaintext,
        diagnostics={
            "top_candidates": [{"key": item.key, "score": item.score} for item in candidates[:5]]
        },
    )


def _run_single_byte_xor() -> DemoResult:
    plaintext = fixtures.SINGLE_BYTE_XOR_PLAINTEXT
    key = fixtures.SINGLE_BYTE_XOR_KEY
    ciphertext = xor.single_byte_xor(plaintext, key)
    candidates = xor.break_single_byte_xor(ciphertext)
    best = candidates[0]
    return _result(
        "break-single-byte-xor",
        ("xor", "english-scoring", "brute-force"),
        "single-byte-xor-local",
        best.plaintext == plaintext,
        "Scoring all 256 possible byte keys makes the correct plaintext stand out.",
        "A one-byte key has almost no entropy and repeats across the entire message.",
        recovered_key=best.key.hex(),
        recovered_plaintext=best.plaintext.decode("ascii"),
        diagnostics={
            # A single-byte XOR is a bijection on byte values, so it permutes the
            # byte histogram without changing the counts: the frequency structure
            # English scoring relies on survives untouched.
            "histogram_preserved_under_xor": (
                sorted(byte_histogram(ciphertext).values())
                == sorted(byte_histogram(best.plaintext).values())
            ),
            "top_candidates": [
                {"key_hex": item.key.hex(), "score": item.score} for item in candidates
            ],
        },
    )


def _run_repeating_xor() -> DemoResult:
    ciphertext = xor.repeating_xor(fixtures.REPEATING_XOR_PLAINTEXT, fixtures.REPEATING_XOR_KEY)
    candidates = xor.break_repeating_xor(ciphertext)
    best = candidates[0]
    return _result(
        "break-repeating-xor",
        ("xor", "hamming-distance", "transposition", "english-scoring"),
        "repeating-xor-local",
        best.plaintext == fixtures.REPEATING_XOR_PLAINTEXT,
        "Normalized Hamming distance suggests the period; transposed columns reduce to byte XOR.",
        "Repeating a short key exposes periodic structure and turns one problem into small ones.",
        recovered_key=best.key.decode("ascii", errors="replace"),
        recovered_plaintext=best.plaintext.decode("ascii"),
        diagnostics={
            "top_candidates": [
                {"key_hex": item.key.hex(), "score": item.score} for item in candidates[:5]
            ]
        },
    )


def _run_two_time_pad() -> DemoResult:
    secure_cipher = xor.otp_encrypt(fixtures.OTP_MESSAGE_ONE, fixtures.OTP_SECURE_PAD)
    secure_roundtrip = xor.otp_encrypt(secure_cipher, fixtures.OTP_SECURE_PAD)

    length = max(len(fixtures.OTP_MESSAGE_ONE), len(fixtures.OTP_MESSAGE_TWO))
    pad = fixtures.OTP_REUSE_PAD
    first = fixtures.OTP_MESSAGE_ONE.ljust(length)
    second = fixtures.OTP_MESSAGE_TWO.ljust(length)
    ciphertext_one = xor.otp_encrypt(first, pad)
    ciphertext_two = xor.otp_encrypt(second, pad)
    recovered_pad = xor.recover_reused_pad(first, ciphertext_one)
    recovered_second = xor.recover_with_pad(ciphertext_two, recovered_pad).rstrip()
    cribs = xor.crib_drag(ciphertext_one, ciphertext_two, fixtures.OTP_CRIB)
    otp_secure = secure_roundtrip == fixtures.OTP_MESSAGE_ONE
    reuse_breaks = recovered_second == fixtures.OTP_MESSAGE_TWO
    return _result(
        "two-time-pad",
        ("one-time-pad", "xor", "key-reuse", "crib-dragging"),
        "two-time-pad-local",
        otp_secure and reuse_breaks,
        "A unique pad round-trips with no cross-message leak; reusing that pad cancels the key.",
        "A one-time pad is secure only when random, message-length, secret, and never reused.",
        recovered_plaintext=recovered_second.decode("ascii"),
        measurements={
            "otp_unique_pad_roundtrip": otp_secure,
            "crib_candidates": len(cribs),
        },
        diagnostics={
            "secure_baseline_plaintext": secure_roundtrip.decode("ascii"),
            "ciphertext_xor_hex": fixed_xor(ciphertext_one, ciphertext_two).hex(),
            "crib_preview": [
                {"offset": offset, "fragment": fragment.decode("ascii")}
                for offset, fragment in cribs[:5]
            ],
        },
    )


def _run_ecb() -> DemoResult:
    ecb = block_modes.aes_ecb_encrypt(fixtures.ECB_PATTERN, fixtures.AES_ECB_KEY, pad=False)
    cbc = block_modes.aes_cbc_encrypt(
        fixtures.ECB_PATTERN, fixtures.AES_ECB_KEY, fixtures.AES_ECB_IV
    )
    ecb_repeats = block_modes.detect_ecb(ecb)
    cbc_repeats = block_modes.detect_ecb(cbc)
    return _result(
        "detect-ecb",
        ("aes", "ecb", "block-patterns"),
        "ecb-pattern-local",
        ecb_repeats and not cbc_repeats,
        "Identical 16-byte plaintext blocks become identical ECB ciphertext blocks.",
        "A secure primitive does not hide patterns when placed in ECB mode.",
        measurements={
            "ecb_repeated": ecb_repeats,
            "cbc_repeated": cbc_repeats,
        },
        diagnostics={
            "ecb_repeated_blocks_detected": ecb_repeats,
            "cbc_repeated_blocks_detected": cbc_repeats,
        },
    )


def _run_cbc_bit_flip() -> DemoResult:
    plaintext = fixtures.CBC_ADMIN_PLAINTEXT
    ciphertext = block_modes.aes_cbc_encrypt(
        plaintext, fixtures.AES_CBC_ADMIN_KEY, fixtures.AES_CBC_ADMIN_IV
    )
    offset = plaintext.index(b"admin=0")
    modified, modified_iv = block_modes.cbc_bit_flip(
        ciphertext, fixtures.AES_CBC_ADMIN_IV, offset, b"admin=0", b"admin=1"
    )
    altered_plaintext = block_modes.aes_cbc_decrypt(
        modified, fixtures.AES_CBC_ADMIN_KEY, modified_iv
    )
    return _result(
        "cbc-bit-flip",
        ("aes", "cbc", "malleability", "integrity"),
        "cbc-admin-local",
        b"admin=1" in altered_plaintext,
        "A ciphertext delta causes a predictable delta in the following plaintext block.",
        "Encryption without authentication is malleable; use AEAD so tampering fails closed.",
        recovered_plaintext=altered_plaintext.decode("ascii", errors="replace"),
        diagnostics={
            "flip_offset": offset,
            "target_field": "admin=0 -> admin=1",
        },
    )


def _run_padding_oracle() -> DemoResult:
    oracle = block_modes.LocalPaddingOracle(fixtures.AES_PADDING_ORACLE_KEY)
    ciphertext = block_modes.aes_cbc_encrypt(
        fixtures.CBC_ORACLE_PLAINTEXT,
        fixtures.AES_PADDING_ORACLE_KEY,
        fixtures.AES_PADDING_ORACLE_IV,
    )
    recovered, query_count = block_modes.padding_oracle_attack(
        fixtures.AES_PADDING_ORACLE_IV, ciphertext, oracle.valid_padding
    )
    return _result(
        "padding-oracle-demo",
        ("aes", "cbc", "padding", "side-channel"),
        "padding-oracle-local",
        recovered == fixtures.CBC_ORACLE_PLAINTEXT,
        "Only a valid/invalid padding bit was exposed, yet every plaintext byte was recovered.",
        "Unauthenticated CBC plus distinguishable errors forms a decryption oracle; use AEAD.",
        recovered_plaintext=recovered.decode("ascii"),
        measurements={"oracle_queries": query_count},
        diagnostics={"oracle_queries": query_count},
    )


def _run_nonce_reuse() -> DemoResult:
    first = block_modes.aes_ctr_crypt(
        fixtures.CTR_MESSAGE_ONE, fixtures.AES_CTR_KEY, fixtures.AES_CTR_NONCE
    )
    second = block_modes.aes_ctr_crypt(
        fixtures.CTR_MESSAGE_TWO, fixtures.AES_CTR_KEY, fixtures.AES_CTR_NONCE
    )
    known_length = min(len(first), len(second))
    keystream = fixed_xor(first[:known_length], fixtures.CTR_MESSAGE_ONE[:known_length])
    recovered = fixed_xor(second[:known_length], keystream)
    expected = fixtures.CTR_MESSAGE_TWO[:known_length]
    return _result(
        "nonce-reuse",
        ("aes", "ctr", "nonce", "key-reuse"),
        "ctr-nonce-reuse-local",
        recovered == expected,
        "Reusing a CTR nonce repeats the keystream, so known plaintext decrypts the overlap.",
        "Nonce uniqueness is a security invariant; the safe API generates nonces internally.",
        recovered_plaintext=recovered.decode("ascii"),
        diagnostics={"ciphertext_xor_hex": block_modes.ctr_reuse_overlap(first, second).hex()},
    )


def _run_length_extension() -> DemoResult:
    key = fixtures.PREFIX_MAC_KEY
    message = fixtures.PREFIX_MAC_MESSAGE
    suffix = fixtures.PREFIX_MAC_SUFFIX
    # Naive MAC = SHA1(key || message): the published digest is resumable hash
    # state, so length extension forges a valid tag for an appended suffix
    # without ever knowing the key.
    tag = integrity.naive_prefix_mac(key, message)
    forged_message, forged_tag = integrity.forge_prefix_mac(
        message, tag, suffix, guessed_key_length=len(key)
    )
    naive_accepts = integrity.verify_naive_prefix_mac(key, forged_message, forged_tag)

    # HMAC over the same data resists the attack: its nested construction means
    # the tag is not resumable state. The attacker's only HMAC value (the tag
    # for the original message) does not authenticate message || suffix, and the
    # rejection is by value, not by a tag-length mismatch.
    genuine_hmac = integrity.hmac_sha256(key, message)
    hmac_self_verifies = integrity.verify_hmac_sha256(key, message, genuine_hmac)
    hmac_forgery_accepted = integrity.verify_hmac_sha256(key, message + suffix, genuine_hmac)

    return _result(
        "length-extension-demo",
        ("mac", "sha1", "length-extension", "hmac"),
        "prefix-mac-local",
        naive_accepts and hmac_self_verifies and not hmac_forgery_accepted,
        "The SHA-1 digest exposes enough internal state to append data without knowing the key.",
        "Hash(key || message) is not a safe MAC; use HMAC or authenticated encryption.",
        recovered_plaintext=forged_message.hex(),
        measurements={
            "naive_mac_accepted": naive_accepts,
            "hmac_self_verifies": hmac_self_verifies,
            "hmac_forgery_accepted": hmac_forgery_accepted,
        },
    )


def _run_timing() -> DemoResult:
    measurement = integrity.measure_timing_leak(fixtures.TIMING_SECRET)
    # A full-prefix match does materially more per-byte work than an immediate
    # first-byte mismatch. Gate on that robust ordering rather than a noisy ratio
    # threshold; the raw ratio is still reported under measurements.
    success = measurement.full_match_median_ns > measurement.first_byte_mismatch_median_ns
    return _result(
        "timing-attack-demo",
        ("side-channel", "timing", "constant-time-comparison"),
        "timing-local",
        success,
        "The early-return comparator spends much longer on a full prefix match.",
        "Secrets can leak through runtime; compare tags with hmac.compare_digest.",
        measurements=dataclasses.asdict(measurement),
        diagnostics={
            "python_timing_is_noisy": True,
            "constant_time_api": "hmac.compare_digest",
        },
    )


def _run_time_seed() -> DemoResult:
    seed = fixtures.TIME_SEED_VALUE
    window = fixtures.TIME_SEED_WINDOW
    observed_offset = fixtures.TIME_SEED_OFFSET
    token = randomness_failures.generate_time_seeded_token(seed)
    recovered = randomness_failures.recover_time_seed(token, seed + observed_offset, window=window)
    return _result(
        "predict-time-seed",
        ("randomness", "time-seed", "brute-force"),
        "time-seeded-rng-local",
        recovered == seed,
        "A small timestamp window reduced the seed search to a few dozen candidates.",
        "Predictable seeds produce predictable keys; use secrets or os.urandom.",
        recovered_key=str(recovered),
        measurements={"window_candidates": 2 * window + 1},
    )


def _run_mt19937() -> DemoResult:
    observed_count = 624  # MT19937 exposes its whole state after one full period
    predict_count = 10
    source = random.Random(fixtures.MT19937_SEED)
    observed = [source.getrandbits(32) for _ in range(observed_count)]
    clone = randomness_failures.clone_mt19937(observed)
    expected = [source.getrandbits(32) for _ in range(predict_count)]
    predicted: list[JSONValue] = [clone.getrandbits(32) for _ in range(predict_count)]
    return _result(
        "predict-mt19937",
        ("randomness", "mersenne-twister", "state-cloning"),
        "mt19937-local",
        predicted == expected,
        "624 outputs reveal the generator's entire internal state and future stream.",
        "Statistical quality is not unpredictability; cryptographic keys need a CSPRNG.",
        recovered_key=f"cloned {observed_count * 32:,}-bit MT19937 state",
        measurements={"observed_outputs": observed_count, "predicted_outputs": predict_count},
        diagnostics={"predicted": predicted},
    )


def _run_safe_api() -> DemoResult:
    key = safe_api.generate_key()
    plaintext = fixtures.SAFE_API_PLAINTEXT
    associated_data = fixtures.SAFE_API_ASSOCIATED_DATA
    package = safe_api.encrypt(key, plaintext, associated_data)
    recovered = safe_api.decrypt(key, safe_api.decode_package(safe_api.encode_package(package)))

    altered = bytearray(package.ciphertext)
    altered[0] ^= 1
    tampering_rejected = False
    try:
        safe_api.decrypt(
            key,
            EncryptedPackage(package.nonce, bytes(altered), package.associated_data),
        )
    except AuthenticationError:
        tampering_rejected = True

    result = _result(
        "do-it-right",
        ("aead", "aes-gcm", "csprng", "fail-closed"),
        "safe-api-local",
        recovered == plaintext and tampering_rejected,
        "AES-GCM encrypts and authenticates; altered packages return no plaintext.",
        "Use a vetted AEAD through a small API that owns nonce generation and verification.",
        recovered_plaintext=recovered.decode("ascii"),
        measurements={
            "tampering_rejected": tampering_rejected,
            "failure_to_safe_api": cast(
                JSONValue,
                [dict(item) for item in SAFE_API_RESOLUTIONS],
            ),
        },
    )
    result.not_for_real_use = False
    return result


def _bound_runner(summary: LessonSummary, runner: DemoRunner) -> DemoRunner:
    def run_demo() -> DemoResult:
        result = runner()
        result.safe_api_reference = summary.safe_api_link
        return result

    return run_demo


def _lesson(
    lesson_id: str,
    title: str,
    concepts: tuple[str, ...],
    fixture_name: str,
    weak_assumption: str,
    summary: LessonSummary,
    runner: DemoRunner,
    explanation: str,
    *,
    is_weak: bool = True,
) -> Lesson:
    return Lesson(
        lesson_id=lesson_id,
        title=title,
        concepts=concepts,
        fixture_name=fixture_name,
        weak_assumption=weak_assumption,
        safety_notice=SAFETY_NOTICE,
        summary=summary,
        run_demo=_bound_runner(summary, runner),
        explanation=explanation,
        is_weak=is_weak,
    )


_LESSONS = (
    _lesson(
        "break-caesar",
        "Break a Caesar shift",
        ("classical-cipher", "frequency-analysis", "brute-force"),
        "caesar-local",
        "A shifted alphabet looks scrambled.",
        _summary(
            "The key and plaintext were recovered.",
            "Only 26 keys exist and letter frequencies survive.",
            "Use authenticated encryption, not a classical cipher.",
        ),
        _run_caesar,
        "Try every shift, score each result as English, "
        "then confirm with letter-frequency analysis.",
    ),
    _lesson(
        "break-substitution",
        "Break simple substitution",
        ("classical-cipher", "frequency-analysis", "word-patterns"),
        "substitution-local",
        "A random alphabet hides language structure.",
        _summary(
            "Word patterns reconstructed the plaintext mapping.",
            "Substitution preserves repetitions, boundaries, and frequencies.",
            "Use authenticated encryption.",
        ),
        _run_substitution,
        "Repeated-letter shapes and common local vocabulary constrain a substitution mapping.",
    ),
    _lesson(
        "break-vigenere",
        "Break Vigenere",
        ("classical-cipher", "kasiski", "index-of-coincidence"),
        "vigenere-local",
        "Several rotating Caesar shifts hide frequency information.",
        _summary(
            "The repeating key and plaintext were recovered.",
            "The key period separates ciphertext into Caesar columns.",
            "Use authenticated encryption with a fresh nonce.",
        ),
        _run_vigenere,
        "Kasiski/IoC reveal likely periods; frequency analysis solves each column.",
    ),
    _lesson(
        "break-single-byte-xor",
        "Break single-byte XOR",
        ("xor", "english-scoring", "brute-force"),
        "single-byte-xor-local",
        "A byte key is enough to obscure readable text.",
        _summary(
            "All 256 keys were scored and the plaintext recovered.",
            "The key space is tiny and the same transformation repeats.",
            "Use AEAD with a securely generated key.",
            DO_IT_RIGHT_SAFE_API,
        ),
        _run_single_byte_xor,
        "Exhaustive search is practical when the entire key space has only 256 values.",
    ),
    _lesson(
        "break-repeating-xor",
        "Break repeating-key XOR",
        ("xor", "hamming-distance", "transposition", "english-scoring"),
        "repeating-xor-local",
        "A short repeated byte key behaves like a stream cipher.",
        _summary(
            "The key period, key, and plaintext were recovered.",
            "Repeating keystream bytes expose periodic statistical structure.",
            "Use AEAD and never construct a repeating keystream.",
        ),
        _run_repeating_xor,
        "Hamming distance estimates the period; transposition creates single-byte XOR columns.",
    ),
    _lesson(
        "two-time-pad",
        "Reuse a one-time pad",
        ("one-time-pad", "xor", "key-reuse", "crib-dragging"),
        "two-time-pad-local",
        "A truly random pad stays safe when reused.",
        _summary(
            "Pad reuse canceled the key and exposed the second message.",
            "The one-time requirement was violated.",
            "Use AEAD with unique nonces and managed keys.",
            DO_IT_RIGHT_SAFE_API,
        ),
        _run_two_time_pad,
        "First show a unique pad round-tripping cleanly, "
        "then reuse that pad to break the second message.",
    ),
    _lesson(
        "detect-ecb",
        "Detect ECB patterns",
        ("aes", "ecb", "block-patterns"),
        "ecb-pattern-local",
        "Using AES alone guarantees confidentiality.",
        _summary(
            "Repeated plaintext blocks remained visible.",
            "ECB encrypts equal blocks independently to equal outputs.",
            "Use an authenticated mode such as AES-GCM.",
        ),
        _run_ecb,
        "Count duplicate ciphertext blocks to identify the deterministic ECB pattern.",
    ),
    _lesson(
        "cbc-bit-flip",
        "Flip bits in CBC",
        ("aes", "cbc", "malleability", "integrity"),
        "cbc-admin-local",
        "Encrypted data cannot be changed meaningfully.",
        _summary(
            "Ciphertext edits changed a chosen plaintext field.",
            "CBC confidentiality provides no integrity.",
            "Use AEAD so modifications fail authentication.",
        ),
        _run_cbc_bit_flip,
        "CBC XORs the prior ciphertext block into plaintext, making edits predictable.",
    ),
    _lesson(
        "padding-oracle-demo",
        "Recover CBC plaintext from a padding oracle",
        ("aes", "cbc", "padding", "side-channel"),
        "padding-oracle-local",
        "Leaking one valid/invalid bit is harmless.",
        _summary(
            "The complete local plaintext was recovered.",
            "Unauthenticated CBC exposed distinguishable padding failures.",
            "Authenticate before releasing plaintext; use AEAD.",
        ),
        _run_padding_oracle,
        "Adaptive edits turn padding validity into information about every plaintext byte.",
    ),
    _lesson(
        "nonce-reuse",
        "Reuse a CTR nonce",
        ("aes", "ctr", "nonce", "key-reuse"),
        "ctr-nonce-reuse-local",
        "A nonce can repeat because it is not secret.",
        _summary(
            "Repeated keystream decrypted the overlapping message.",
            "CTR key/nonce reuse repeats the stream.",
            "Use an API that generates fresh nonces internally.",
            FRESH_NONCE_ENCRYPT,
        ),
        _run_nonce_reuse,
        "With a repeated CTR nonce, known plaintext reveals the shared keystream.",
    ),
    _lesson(
        "length-extension-demo",
        "Extend a naive prefix MAC",
        ("mac", "sha1", "length-extension", "hmac"),
        "prefix-mac-local",
        "Hashing key || message creates a MAC.",
        _summary(
            "A valid tag was forged without the key.",
            "Merkle-Damgard state can continue from a published digest.",
            "Use HMAC or AEAD.",
            AEAD_OR_HMAC,
        ),
        _run_length_extension,
        "The digest acts as resumable hash state; HMAC's nested construction prevents this.",
    ),
    _lesson(
        "timing-attack-demo",
        "Measure an early-return timing leak",
        ("side-channel", "timing", "constant-time-comparison"),
        "timing-local",
        "Comparison implementation details cannot reveal secrets.",
        _summary(
            "Runtime distinguished an early mismatch from a full match.",
            "The comparator returned early and work depended on secret agreement.",
            "Use hmac.compare_digest and avoid secret-dependent control flow.",
            HMAC_COMPARE_DIGEST,
        ),
        _run_timing,
        "Repeated trials reveal a noisy but clear runtime difference.",
    ),
    _lesson(
        "predict-time-seed",
        "Recover a time-seeded key",
        ("randomness", "time-seed", "brute-force"),
        "time-seeded-rng-local",
        "Current time is an unpredictable seed.",
        _summary(
            "The seed was recovered from a small time window.",
            "Timestamp entropy and uncertainty were tiny.",
            "Generate keys with secrets or the vetted library.",
            GENERATE_KEY_API,
        ),
        _run_time_seed,
        "Search the plausible local timestamp window and regenerate each output.",
    ),
    _lesson(
        "predict-mt19937",
        "Clone Python's Mersenne Twister",
        ("randomness", "mersenne-twister", "state-cloning"),
        "mt19937-local",
        "A high-quality simulation PRNG is suitable for keys.",
        _summary(
            "Future outputs were predicted exactly.",
            "MT19937 output reveals its recoverable internal state.",
            "Use secrets or os.urandom for cryptographic randomness.",
            GENERATE_KEY_API,
        ),
        _run_mt19937,
        "Invert the tempering transform for 624 outputs, then load the recovered state.",
    ),
    _lesson(
        "do-it-right",
        "Use authenticated encryption",
        ("aead", "aes-gcm", "csprng", "fail-closed"),
        "safe-api-local",
        "Callers should assemble cipher modes, nonces, padding, and MACs themselves.",
        _summary(
            "Tampering produced an explicit failure and no plaintext.",
            "AEAD binds ciphertext, nonce, and associated data under one audited construction.",
            "Authenticated encryption with internal nonce generation and verification.",
            DO_IT_RIGHT_SAFE_API,
        ),
        _run_safe_api,
        "AES-GCM with internal nonce generation resolves the preceding failure modes side by side.",
        is_weak=False,
    ),
)

SAFE_API_RESOLUTIONS = _safe_api_resolutions_for(_LESSONS)

LESSONS: dict[str, Lesson] = {lesson.lesson_id: lesson for lesson in _LESSONS}


def list_lessons() -> tuple[Lesson, ...]:
    return tuple(LESSONS.values())


def get_lesson(lesson_id: str) -> Lesson:
    try:
        return LESSONS[lesson_id]
    except KeyError as exc:
        available = ", ".join(LESSONS)
        raise UnknownLessonError(
            f"unknown lesson {lesson_id!r}; available lessons: {available}"
        ) from exc


def run_lesson(lesson_id: str) -> DemoResult:
    return get_lesson(lesson_id).run_demo()


def run_all_lessons() -> Iterable[DemoResult]:
    for lesson in list_lessons():
        yield lesson.run_demo()
