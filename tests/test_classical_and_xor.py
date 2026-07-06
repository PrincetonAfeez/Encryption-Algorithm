"""Tests for the classical and xor modules."""

from feltcrypto import fixtures
from feltcrypto.weak import classical, xor


def test_caesar_round_trip_and_break() -> None:
    ciphertext = classical.caesar_encrypt(fixtures.CAESAR_PLAINTEXT, fixtures.CAESAR_KEY)
    assert classical.caesar_decrypt(ciphertext, fixtures.CAESAR_KEY) == fixtures.CAESAR_PLAINTEXT
    assert classical.break_caesar(ciphertext)[0].plaintext == fixtures.CAESAR_PLAINTEXT


def test_substitution_round_trip_and_pattern_attack() -> None:
    ciphertext = classical.substitution_encrypt(
        fixtures.SUBSTITUTION_PLAINTEXT, fixtures.SUBSTITUTION_ALPHABET
    )
    assert (
        classical.substitution_decrypt(ciphertext, fixtures.SUBSTITUTION_ALPHABET)
        == fixtures.SUBSTITUTION_PLAINTEXT
    )
    result = classical.break_substitution(ciphertext, fixtures.SUBSTITUTION_VOCABULARY)
    assert result.plaintext == fixtures.SUBSTITUTION_PLAINTEXT


def test_vigenere_round_trip_and_break() -> None:
    ciphertext = classical.vigenere_encrypt(fixtures.VIGENERE_PLAINTEXT, fixtures.VIGENERE_KEY)
    assert (
        classical.vigenere_decrypt(ciphertext, fixtures.VIGENERE_KEY) == fixtures.VIGENERE_PLAINTEXT
    )
    result = classical.break_vigenere(ciphertext)[0]
    assert result.key == fixtures.VIGENERE_KEY
    assert result.plaintext == fixtures.VIGENERE_PLAINTEXT


def test_vigenere_round_trips_with_non_letter_key_characters() -> None:
    plaintext = "Meet me at the harbor at noon"
    for key in ("OR GE", "my-key", "Key 1 2 3"):
        ciphertext = classical.vigenere_encrypt(plaintext, key)
        assert classical.vigenere_decrypt(ciphertext, key) == plaintext


def test_single_and_repeating_xor_breaks() -> None:
    plaintext = b"English scoring recovers a one byte XOR key."
    ciphertext = xor.single_byte_xor(plaintext, 42)
    assert xor.break_single_byte_xor(ciphertext)[0].plaintext == plaintext

    repeated = xor.repeating_xor(fixtures.REPEATING_XOR_PLAINTEXT, fixtures.REPEATING_XOR_KEY)
    result = xor.break_repeating_xor(repeated)[0]
    assert result.key == fixtures.REPEATING_XOR_KEY
    assert result.plaintext == fixtures.REPEATING_XOR_PLAINTEXT


def test_breakers_are_robust_to_short_and_non_ascii_inputs() -> None:
    # Short repeating-XOR ciphertext must not raise on chunk alignment.
    short_cipher = xor.repeating_xor(b"Attack at dawn, retreat at dusk, hold the line.", b"KEY")
    assert xor.break_repeating_xor(short_cipher)

    # Short Vigenere text must not divide by zero on empty columns.
    assert isinstance(classical.break_vigenere("Hi there friend"), list)

    # Non-ASCII input must not raise when scoring candidates as English.
    assert classical.break_caesar(classical.caesar_encrypt("cafe au lait, naïve", 5))
    assert isinstance(classical.break_vigenere("naïve café résumé"), list)


def test_one_time_pad_requires_equal_length_and_reuse_exposes_messages() -> None:
    pad = bytes(range(len(fixtures.OTP_MESSAGE_ONE)))
    ciphertext = xor.otp_encrypt(fixtures.OTP_MESSAGE_ONE, pad)
    assert xor.otp_encrypt(ciphertext, pad) == fixtures.OTP_MESSAGE_ONE

    known = fixtures.OTP_MESSAGE_ONE
    other = fixtures.OTP_MESSAGE_TWO[: len(known)]
    reused = bytes((index * 17) % 256 for index in range(len(known)))
    first = xor.otp_encrypt(known, reused)
    second = xor.otp_encrypt(other, reused[: len(other)])
    recovered_pad = xor.recover_reused_pad(known, first)
    assert xor.recover_with_pad(second, recovered_pad) == other
