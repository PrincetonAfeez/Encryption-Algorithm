"""Byte, encoding, padding, chunking, and scoring foundations """

from __future__ import annotations

import base64
import binascii
import math
from collections import Counter
from collections.abc import Sequence

from feltcrypto.errors import PaddingError, ParseError

# Relative frequencies plus a strong allowance for spaces. The exact values are
# less important than using one consistent, explainable score across lessons.
ENGLISH_FREQUENCY = {
    " ": 0.182,
    "e": 0.102,
    "t": 0.075,
    "a": 0.065,
    "o": 0.061,
    "i": 0.057,
    "n": 0.057,
    "s": 0.053,
    "h": 0.049,
    "r": 0.049,
    "d": 0.034,
    "l": 0.033,
    "u": 0.022,
}


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ParseError("invalid hexadecimal text") from exc


def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ParseError("invalid Base64 text") from exc


def parse_bytes(value: str, representation: str) -> bytes:
    """Parse an explicit CLI representation without guessing or coercion."""

    if representation == "text":
        return value.encode("utf-8")
    if representation == "hex":
        return hex_decode(value)
    if representation == "base64":
        return base64_decode(value)
    raise ParseError("representation must be one of: text, hex, base64")


def fixed_xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("fixed XOR requires equal-length byte strings")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("Hamming distance requires equal-length byte strings")
    return sum((a ^ b).bit_count() for a, b in zip(left, right, strict=True))


def chunks(data: bytes, size: int, *, require_full: bool = False) -> list[bytes]:
    if size <= 0:
        raise ValueError("chunk size must be positive")
    result = [data[index : index + size] for index in range(0, len(data), size)]
    if require_full and result and len(result[-1]) != size:
        raise ValueError("input is not an exact multiple of the chunk size")
    return result


def transpose_blocks(blocks: Sequence[bytes]) -> list[bytes]:
    """Collect the i-th byte of every block into output column i.

    Transposing repeating-key-XOR blocks turns each key position into its own
    single-byte-XOR column, which can then be solved independently.
    """

    width = max((len(block) for block in blocks), default=0)
    return [bytes(block[i] for block in blocks if i < len(block)) for i in range(width)]


def byte_histogram(data: bytes) -> dict[int, int]:
    return dict(Counter(data))


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Append PKCS#7 padding to reach the next block boundary.

    Already-aligned input gains a whole extra block of padding so that the
    length is always recoverable from the final byte.
    """

    if not 1 <= block_size <= 255:
        raise ValueError("block size must be between 1 and 255")
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size:
        raise PaddingError("padded data must be non-empty and block aligned")
    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise PaddingError("invalid PKCS#7 padding length")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise PaddingError("invalid PKCS#7 padding bytes")
    return data[:-padding_length]


def english_score(data: bytes) -> float:
    """Return a higher score for plausible English byte strings."""

    if not data:
        return float("-inf")
    score = 0.0
    lowered = data.lower()
    for byte in lowered:
        char = chr(byte)
        if char in ENGLISH_FREQUENCY:
            score += math.log(ENGLISH_FREQUENCY[char] + 0.01)
        elif 97 <= byte <= 122:
            score += math.log(0.018)
        elif byte in b".,'!?;:-\n":
            score += math.log(0.012)
        elif 32 <= byte <= 126:
            score += math.log(0.003)
        else:
            score -= 12.0
    return score / len(data)


def index_of_coincidence(text: str) -> float:
    """Probability that two letters drawn at random match (~0.066 for English).

    A value near 0.038 suggests a flat, polyalphabetic distribution, which is
    how Vigenere key-length search tells right periods from wrong ones.
    """

    letters = [char for char in text.upper() if char.isalpha()]
    count = len(letters)
    if count < 2:
        return 0.0
    frequencies = Counter(letters)
    numerator = sum(value * (value - 1) for value in frequencies.values())
    return numerator / (count * (count - 1))


def repeated_block_count(data: bytes, block_size: int = 16) -> int:
    """Count repeated equal-size blocks, the telltale signature of ECB mode."""

    blocks = chunks(data, block_size)
    frequencies = Counter(blocks)
    return sum(count - 1 for count in frequencies.values() if count > 1)
