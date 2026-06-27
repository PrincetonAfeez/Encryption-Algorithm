"""Integrity construction and timing failures against local toy targets.

NOT SECURE. NEVER USE FOR REAL PROTECTION.
"""

from __future__ import annotations

import hashlib
import hmac
import statistics
import time
from dataclasses import dataclass

from feltcrypto.weak.sha1 import (
    educational_sha1,
    sha1_padding,
    state_from_digest,
)


def naive_prefix_mac(key: bytes, message: bytes) -> bytes:
    """Build the broken MAC ``SHA1(key || message)`` (vulnerable, for the demo)."""

    return educational_sha1(key + message)


def verify_naive_prefix_mac(key: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(naive_prefix_mac(key, message), tag)


def forge_prefix_mac(
    message: bytes,
    tag: bytes,
    suffix: bytes,
    guessed_key_length: int,
) -> tuple[bytes, bytes]:
    """Length-extend a prefix-MAC tag to authenticate an appended suffix.

    The published digest is resumable hash state, so an attacker can continue
    hashing from it and append data without ever knowing the key.
    """

    if guessed_key_length <= 0:
        raise ValueError("guessed key length must be positive")
    glue = sha1_padding(guessed_key_length + len(message))
    forged_message = message + glue + suffix
    prior_length = guessed_key_length + len(message) + len(glue)
    forged_tag = educational_sha1(
        suffix,
        state=state_from_digest(tag),
        prior_length=prior_length,
    )
    return forged_message, forged_tag


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac_sha256(key: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(hmac_sha256(key, message), tag)


def insecure_compare(expected: bytes, supplied: bytes, work_factor: int = 700) -> bool:
    """Early-return comparison with deterministic per-byte CPU work."""

    if len(expected) != len(supplied):
        return False
    accumulator = 0
    for expected_byte, supplied_byte in zip(expected, supplied, strict=True):
        if expected_byte != supplied_byte:
            return False
        for value in range(work_factor):
            accumulator ^= (value * 33 + expected_byte) & 0xFF
    return accumulator >= 0


@dataclass(frozen=True)
class TimingMeasurement:
    first_byte_mismatch_median_ns: float
    full_match_median_ns: float
    ratio: float
    trials: int


def measure_timing_leak(
    expected: bytes, *, trials: int = 80, work_factor: int = 700
) -> TimingMeasurement:
    if not expected:
        raise ValueError("timing demonstration requires a non-empty secret")
    mismatch = bytes([expected[0] ^ 1]) + expected[1:]
    mismatch_times: list[int] = []
    match_times: list[int] = []
    for _ in range(trials):
        start = time.perf_counter_ns()
        insecure_compare(expected, mismatch, work_factor)
        mismatch_times.append(time.perf_counter_ns() - start)

        start = time.perf_counter_ns()
        insecure_compare(expected, expected, work_factor)
        match_times.append(time.perf_counter_ns() - start)

    mismatch_median = statistics.median(mismatch_times)
    match_median = statistics.median(match_times)
    return TimingMeasurement(
        first_byte_mismatch_median_ns=mismatch_median,
        full_match_median_ns=match_median,
        ratio=match_median / max(mismatch_median, 1),
        trials=trials,
    )


def constant_time_compare(expected: bytes, supplied: bytes) -> bool:
    return hmac.compare_digest(expected, supplied)
