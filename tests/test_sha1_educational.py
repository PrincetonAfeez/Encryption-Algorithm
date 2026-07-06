"""Tests for the educational SHA-1 implementation."""

import hashlib

import pytest

from feltcrypto.weak.integrity import forge_prefix_mac, naive_prefix_mac
from feltcrypto.weak.sha1 import (
    educational_sha1,
    sha1_padding,
    state_from_digest,
)


def test_sha1_padding_lengths() -> None:
    for length in (0, 1, 55, 56, 63, 64, 1000):
        padding = sha1_padding(length)
        assert padding.startswith(b"\x80")
        assert (length + len(padding)) % 64 == 0


def test_state_from_digest_round_trip() -> None:
    digest = educational_sha1(b"continued")
    state = state_from_digest(digest)
    assert len(state) == 5


def test_state_from_digest_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="20 bytes"):
        state_from_digest(b"too short")


def test_educational_sha1_matches_hashlib_for_various_lengths() -> None:
    messages = (
        b"a",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"\x00" * 64,
    )
    for message in messages:
        assert educational_sha1(message) == hashlib.sha1(message).digest()


def test_length_extension_uses_resumable_state() -> None:
    key = b"secret"
    message = b"payload"
    suffix = b"extra"
    tag = naive_prefix_mac(key, message)
    forged_message, forged_tag = forge_prefix_mac(message, tag, suffix, len(key))
    assert len(forged_tag) == 20
    assert suffix in forged_message
