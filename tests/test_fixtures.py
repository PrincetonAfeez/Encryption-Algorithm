"""Verify bundled fixture constants are present and well-formed."""

import feltcrypto.fixtures as fixtures


def test_fixture_constants_are_non_empty() -> None:
    string_fixtures = (
        "LONG_ENGLISH",
        "CAESAR_PLAINTEXT",
        "VIGENERE_PLAINTEXT",
        "VIGENERE_KEY",
        "SUBSTITUTION_PLAINTEXT",
        "SUBSTITUTION_ALPHABET",
    )
    for name in string_fixtures:
        value = getattr(fixtures, name)
        assert isinstance(value, str)
        assert value.strip()

    bytes_fixtures = (
        "REPEATING_XOR_PLAINTEXT",
        "REPEATING_XOR_KEY",
        "SINGLE_BYTE_XOR_PLAINTEXT",
        "OTP_MESSAGE_ONE",
        "OTP_MESSAGE_TWO",
        "ECB_PATTERN",
        "CBC_ADMIN_PLAINTEXT",
        "CBC_ORACLE_PLAINTEXT",
        "CTR_MESSAGE_ONE",
        "CTR_MESSAGE_TWO",
        "PREFIX_MAC_KEY",
        "PREFIX_MAC_MESSAGE",
        "SAFE_API_PLAINTEXT",
    )
    for name in bytes_fixtures:
        value = getattr(fixtures, name)
        assert isinstance(value, bytes)
        assert value


def test_substitution_alphabet_is_a_permutation() -> None:
    assert len(fixtures.SUBSTITUTION_ALPHABET) == 26
    assert len(set(fixtures.SUBSTITUTION_ALPHABET.upper())) == 26


def test_vocabulary_entries_are_lowercase_words() -> None:
    assert fixtures.SUBSTITUTION_VOCABULARY
    assert all(word.islower() and word.isalpha() for word in fixtures.SUBSTITUTION_VOCABULARY)
