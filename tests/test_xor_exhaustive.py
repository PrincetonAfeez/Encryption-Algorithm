"""Exhaustive tests for XOR ciphers, OTP reuse, and crib dragging."""

import pytest

from feltcrypto import fixtures
from feltcrypto.weak import xor


def test_repeating_xor_and_single_byte_validation() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        xor.repeating_xor(b"data", b"")
    with pytest.raises(ValueError, match="between 0 and 255"):
        xor.single_byte_xor(b"data", 256)


def test_normalized_keysize_distances_skips_single_block_key_sizes() -> None:
    assert xor.normalized_keysize_distances(b"ab") == []
    # key_size=5 yields one sample block for a 9-byte input and is skipped internally.
    distances = xor.normalized_keysize_distances(b"\x00" * 9, minimum=1, maximum=5)
    assert 5 not in {key_size for key_size, _distance in distances}
    assert distances


def test_otp_and_pad_recovery_validation() -> None:
    with pytest.raises(ValueError, match="exactly as long"):
        xor.otp_encrypt(b"short", b"longer pad")
    with pytest.raises(ValueError, match="equal length"):
        xor.recover_reused_pad(b"abc", b"ab")
    with pytest.raises(ValueError, match="shorter than ciphertext"):
        xor.recover_with_pad(b"toolong", b"x")


def test_crib_drag_finds_printable_fragments() -> None:
    pad = fixtures.OTP_REUSE_PAD
    first = xor.otp_encrypt(fixtures.OTP_MESSAGE_ONE, pad[: len(fixtures.OTP_MESSAGE_ONE)])
    second = xor.otp_encrypt(fixtures.OTP_MESSAGE_TWO, pad[: len(fixtures.OTP_MESSAGE_TWO)])
    candidates = xor.crib_drag(first, second, fixtures.OTP_CRIB)
    assert candidates
    assert all(all(32 <= byte <= 126 for byte in fragment) for _offset, fragment in candidates)


def test_xor_candidate_dataclass_fields() -> None:
    candidate = xor.XORCandidate(b"K", b"plain", 1.5)
    assert candidate.key == b"K"
    assert candidate.plaintext == b"plain"
    assert candidate.score == 1.5


def test_break_single_byte_xor_respects_top_n() -> None:
    ciphertext = xor.single_byte_xor(
        fixtures.SINGLE_BYTE_XOR_PLAINTEXT, fixtures.SINGLE_BYTE_XOR_KEY
    )
    assert len(xor.break_single_byte_xor(ciphertext, top_n=3)) == 3


def test_break_repeating_xor_collapses_repeated_key_period() -> None:
    doubled_key = fixtures.REPEATING_XOR_KEY * 2
    ciphertext = xor.repeating_xor(fixtures.REPEATING_XOR_PLAINTEXT, doubled_key)
    result = xor.break_repeating_xor(ciphertext)[0]
    assert result.plaintext == fixtures.REPEATING_XOR_PLAINTEXT
