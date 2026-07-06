"""Exhaustive tests for classical cipher helpers and attack edge cases."""

import pytest

from feltcrypto import fixtures
from feltcrypto.weak import classical


def test_shift_char_preserves_non_letters() -> None:
    assert classical.caesar_encrypt("Hello, World! 123", 3) == "Khoor, Zruog! 123"


def test_substitution_round_trip_and_invalid_alphabet() -> None:
    ciphertext = classical.substitution_encrypt(
        fixtures.SUBSTITUTION_PLAINTEXT,
        fixtures.SUBSTITUTION_ALPHABET,
    )
    assert (
        classical.substitution_decrypt(ciphertext, fixtures.SUBSTITUTION_ALPHABET)
        == fixtures.SUBSTITUTION_PLAINTEXT
    )
    with pytest.raises(ValueError, match="A-Z exactly once"):
        classical.substitution_encrypt("abc", "ABC")


def test_word_pattern_maps_repeated_letters() -> None:
    assert classical.word_pattern("hello") == (0, 1, 2, 2, 3)
    assert classical.word_pattern("test") == (0, 1, 2, 0)


def test_break_substitution_rejects_unknown_vocabulary_patterns() -> None:
    alphabet = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ciphertext = classical.substitution_encrypt("zzzzzzzzzzzzzzzzzzzz", alphabet)
    with pytest.raises(ValueError, match="vocabulary"):
        classical.break_substitution(ciphertext, fixtures.SUBSTITUTION_VOCABULARY)


def test_break_substitution_raises_when_mappings_conflict() -> None:
    with pytest.raises(ValueError, match="no substitution candidate"):
        classical.break_substitution("zz yy", ("aa", "ab"))


def test_vigenere_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="letters"):
        classical.vigenere_encrypt("hello", "123")


def test_break_vigenere_returns_empty_for_letterless_ciphertext() -> None:
    assert classical.break_vigenere("12345!!!") == []


def test_break_vigenere_handles_empty_key_columns() -> None:
    candidates = classical.break_vigenere("ABCDEF", maximum_key_length=6)
    assert candidates
    assert candidates[0].plaintext


def test_caesar_frequency_guess_and_confidence_gap() -> None:
    ciphertext = classical.caesar_encrypt(fixtures.CAESAR_PLAINTEXT, fixtures.CAESAR_KEY)
    assert classical.caesar_frequency_guess(ciphertext) == fixtures.CAESAR_KEY
    with pytest.raises(ValueError, match="no letters"):
        classical.caesar_frequency_guess("12345")

    single = classical.break_caesar(ciphertext, top_n=1)
    assert classical.confidence_gap(single) == float("inf")
    ranked = classical.break_caesar(ciphertext, top_n=3)
    assert classical.confidence_gap(ranked) >= 0.0


def test_kasiski_votes_supports_key_length_search() -> None:
    repeated = classical.vigenere_encrypt("the the the the the", "KEY")
    votes = classical._kasiski_votes(
        "".join(char for char in repeated.upper() if char.isalpha()),
        12,
    )
    assert votes.total() >= 0


def test_chi_squared_empty_column_returns_infinity() -> None:
    assert classical._chi_squared_for_shift("", 0) == float("inf")
