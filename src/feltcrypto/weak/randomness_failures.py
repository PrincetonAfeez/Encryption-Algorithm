"""Predictable RNG demonstrations against locally generated values

NOT SECURE. NEVER USE FOR REAL KEY GENERATION.
"""

from __future__ import annotations

import random

from feltcrypto.randomness import insecure_time_seeded_rng

MASK32 = 0xFFFFFFFF


def generate_time_seeded_token(seed_seconds: int) -> int:
    return insecure_time_seeded_rng(seed_seconds).getrandbits(32)


def recover_time_seed(token: int, approximate_seed: int, window: int) -> int | None:
    for candidate in range(approximate_seed - window, approximate_seed + window + 1):
        if generate_time_seeded_token(candidate) == token:
            return candidate
    return None


def _undo_right_shift_xor(value: int, shift: int) -> int:
    result = value
    for _ in range(8):
        result = value ^ (result >> shift)
    return result & MASK32


def _undo_left_shift_xor_mask(value: int, shift: int, mask: int) -> int:
    result = value
    for _ in range(8):
        result = value ^ ((result << shift) & mask)
    return result & MASK32


def untemper_mt19937(value: int) -> int:
    value = _undo_right_shift_xor(value, 18)
    value = _undo_left_shift_xor_mask(value, 15, 0xEFC60000)
    value = _undo_left_shift_xor_mask(value, 7, 0x9D2C5680)
    return _undo_right_shift_xor(value, 11)


def clone_mt19937(observed_outputs: list[int]) -> random.Random:
    if len(observed_outputs) != 624:
        raise ValueError("exactly 624 consecutive 32-bit outputs are required")
    state = tuple(untemper_mt19937(value) for value in observed_outputs)
    clone = random.Random()
    # Reuse CPython's own state-format version instead of hardcoding it, so the
    # demo keeps working if a future release changes the Mersenne Twister layout.
    version = clone.getstate()[0]
    clone.setstate((version, (*state, 624), None))
    return clone
