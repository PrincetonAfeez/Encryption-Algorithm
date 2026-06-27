"""Small educational SHA-1 with injectable state for length-extension study.

NOT CONSTANT-TIME. NOT AUDITED. NEVER USE FOR REAL PROTECTION.
"""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF
INITIAL_STATE = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)


def _left_rotate(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & MASK32


def sha1_padding(message_length: int) -> bytes:
    padding = b"\x80"
    padding += b"\x00" * ((56 - (message_length + 1) % 64) % 64)
    return padding + struct.pack(">Q", message_length * 8)


def educational_sha1(
    data: bytes,
    *,
    state: tuple[int, int, int, int, int] = INITIAL_STATE,
    prior_length: int = 0,
) -> bytes:
    """Hash data, optionally continuing from a prior internal state."""

    message = data + sha1_padding(prior_length + len(data))
    h0, h1, h2, h3, h4 = state
    for offset in range(0, len(message), 64):
        chunk = message[offset : offset + 64]
        words = list(struct.unpack(">16I", chunk)) + [0] * 64
        for index in range(16, 80):
            words[index] = _left_rotate(
                words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16],
                1,
            )

        a, b, c, d, e = h0, h1, h2, h3, h4
        for index in range(80):
            if index < 20:
                function = (b & c) | ((~b) & d)
                constant = 0x5A827999
            elif index < 40:
                function = b ^ c ^ d
                constant = 0x6ED9EBA1
            elif index < 60:
                function = (b & c) | (b & d) | (c & d)
                constant = 0x8F1BBCDC
            else:
                function = b ^ c ^ d
                constant = 0xCA62C1D6
            temporary = (_left_rotate(a, 5) + function + e + constant + words[index]) & MASK32
            e = d
            d = c
            c = _left_rotate(b, 30)
            b = a
            a = temporary

        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32

    return struct.pack(">5I", h0, h1, h2, h3, h4)


def state_from_digest(digest: bytes) -> tuple[int, int, int, int, int]:
    if len(digest) != 20:
        raise ValueError("SHA-1 digest must be 20 bytes")
    return struct.unpack(">5I", digest)
