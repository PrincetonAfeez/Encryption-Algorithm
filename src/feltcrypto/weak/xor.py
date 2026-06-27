"""XOR ciphers, key-reuse failures, and attacks on local fixtures.

NOT SECURE. NEVER USE FOR REAL PROTECTION.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from feltcrypto.foundations import (
    chunks,
    english_score,
    fixed_xor,
    hamming_distance,
    transpose_blocks,
)


@dataclass(frozen=True)
class XORCandidate:
    key: bytes
    plaintext: bytes
    score: float


def repeating_xor(data: bytes, key: bytes) -> bytes:
    """XOR data against the key repeated cyclically (Vigenere over bytes)."""

    if not key:
        raise ValueError("XOR key must not be empty")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def single_byte_xor(data: bytes, key: int) -> bytes:
    """XOR every byte with one constant key byte (a 256-value keyspace)."""

    if not 0 <= key <= 255:
        raise ValueError("single-byte XOR key must be between 0 and 255")
    return bytes(byte ^ key for byte in data)


def break_single_byte_xor(ciphertext: bytes, top_n: int = 5) -> list[XORCandidate]:
    """Score all 256 possible key bytes and return the most English-looking."""

    candidates = [
        XORCandidate(bytes([key]), single_byte_xor(ciphertext, key), 0.0) for key in range(256)
    ]
    scored = [
        XORCandidate(item.key, item.plaintext, english_score(item.plaintext)) for item in candidates
    ]
    return sorted(scored, key=lambda item: item.score, reverse=True)[:top_n]


def normalized_keysize_distances(
    ciphertext: bytes, minimum: int = 2, maximum: int = 40
) -> list[tuple[int, float]]:
    """Rank candidate key sizes by normalized Hamming distance, smallest first.

    Blocks one true key apart differ in fewer bits than blocks split across the
    period, so the real key size tends to surface near the top.
    """

    distances: list[tuple[int, float]] = []
    for key_size in range(minimum, min(maximum, len(ciphertext) // 2) + 1):
        # Sample as many whole blocks as the ciphertext provides (up to eight)
        # so short inputs stay block-aligned instead of raising on a partial
        # final chunk. At least two blocks are needed to form a distance pair.
        block_count = min(8, len(ciphertext) // key_size)
        if block_count < 2:
            continue
        samples = chunks(ciphertext[: block_count * key_size], key_size, require_full=True)
        pair_distances = [
            hamming_distance(left, right) / key_size for left, right in pairwise(samples)
        ]
        distances.append((key_size, sum(pair_distances) / len(pair_distances)))
    return sorted(distances, key=lambda item: item[1])


def break_repeating_xor(ciphertext: bytes, maximum_key_size: int = 40) -> list[XORCandidate]:
    """Recover a repeating XOR key: guess the size, transpose, solve each column.

    Each transposed column is a single-byte XOR, so the hard problem collapses
    into many easy ones.
    """

    keysize_candidates = normalized_keysize_distances(ciphertext, maximum=maximum_key_size)[:12]
    candidates: list[XORCandidate] = []
    for key_size, _ in keysize_candidates:
        columns = transpose_blocks(chunks(ciphertext, key_size))
        key = b"".join(break_single_byte_xor(column, top_n=1)[0].key for column in columns)
        for period in range(1, len(key) + 1):
            if len(key) % period == 0 and key == key[:period] * (len(key) // period):
                key = key[:period]
                break
        plaintext = repeating_xor(ciphertext, key)
        # Prefer the simplest key when equally good multiples describe the same stream.
        score = english_score(plaintext) - len(key) * 0.0004
        candidates.append(XORCandidate(key, plaintext, score))
    return sorted(candidates, key=lambda item: item.score, reverse=True)


def otp_encrypt(message: bytes, pad: bytes) -> bytes:
    if len(message) != len(pad):
        raise ValueError("a one-time pad must be exactly as long as the message")
    return fixed_xor(message, pad)


def recover_reused_pad(known_plaintext: bytes, ciphertext: bytes) -> bytes:
    if len(known_plaintext) != len(ciphertext):
        raise ValueError("known plaintext and ciphertext must have equal length")
    return fixed_xor(known_plaintext, ciphertext)


def recover_with_pad(ciphertext: bytes, pad: bytes) -> bytes:
    if len(ciphertext) > len(pad):
        raise ValueError("pad is shorter than ciphertext")
    return fixed_xor(ciphertext, pad[: len(ciphertext)])


def crib_drag(ciphertext_one: bytes, ciphertext_two: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """Return plausible counterpart fragments from two bundled ciphertexts."""

    overlap = fixed_xor(
        ciphertext_one[: min(len(ciphertext_one), len(ciphertext_two))],
        ciphertext_two[: min(len(ciphertext_one), len(ciphertext_two))],
    )
    candidates: list[tuple[int, bytes]] = []
    for offset in range(len(overlap) - len(crib) + 1):
        fragment = fixed_xor(overlap[offset : offset + len(crib)], crib)
        if all(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in fragment):
            candidates.append((offset, fragment))
    return candidates
