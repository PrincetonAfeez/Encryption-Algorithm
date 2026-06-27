"""Randomness policy: secure defaults and explicitly named insecure demos."""

from __future__ import annotations

import random
import secrets


def secure_bytes(length: int) -> bytes:
    if length <= 0:
        raise ValueError("secure byte length must be positive")
    return secrets.token_bytes(length)


def insecure_time_seeded_rng(seed_seconds: int) -> random.Random:
    """Return a predictable RNG for a local failure demonstration only."""

    return random.Random(seed_seconds)
