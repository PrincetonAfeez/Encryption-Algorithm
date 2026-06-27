import pytest

from feltcrypto import fixtures
from feltcrypto.weak import block_modes


def test_ecb_and_cbc_round_trip_and_detector() -> None:
    key = b"K" * 16
    iv = b"I" * 16
    ecb_ciphertext = block_modes.aes_ecb_encrypt(fixtures.ECB_PATTERN, key, pad=False)
    assert block_modes.aes_ecb_decrypt(ecb_ciphertext, key, unpad=False) == fixtures.ECB_PATTERN
    assert block_modes.detect_ecb(ecb_ciphertext)

    cbc_ciphertext = block_modes.aes_cbc_encrypt(fixtures.ECB_PATTERN, key, iv)
    assert block_modes.aes_cbc_decrypt(cbc_ciphertext, key, iv) == fixtures.ECB_PATTERN
    assert not block_modes.detect_ecb(cbc_ciphertext)


def test_cbc_bit_flip_changes_chosen_field() -> None:
    key = b"C" * 16
    iv = b"V" * 16
    plaintext = fixtures.CBC_ADMIN_PLAINTEXT
    ciphertext = block_modes.aes_cbc_encrypt(plaintext, key, iv)
    modified, modified_iv = block_modes.cbc_bit_flip(
        ciphertext,
        iv,
        plaintext.index(b"admin=0"),
        b"admin=0",
        b"admin=1",
    )
    assert b"admin=1" in block_modes.aes_cbc_decrypt(modified, key, modified_iv)


def test_cbc_bit_flip_rejects_out_of_range_offset() -> None:
    key = b"C" * 16
    iv = b"V" * 16
    ciphertext = block_modes.aes_cbc_encrypt(b"short message", key, iv)
    with pytest.raises(ValueError, match="past the ciphertext"):
        block_modes.cbc_bit_flip(ciphertext, iv, 9999, b"x", b"y")


def test_padding_oracle_recovers_local_plaintext() -> None:
    key = b"P" * 16
    iv = b"O" * 16
    ciphertext = block_modes.aes_cbc_encrypt(fixtures.CBC_ORACLE_PLAINTEXT, key, iv)
    oracle = block_modes.LocalPaddingOracle(key)
    recovered, queries = block_modes.padding_oracle_attack(iv, ciphertext, oracle.valid_padding)
    assert recovered == fixtures.CBC_ORACLE_PLAINTEXT
    assert queries > len(recovered)


def test_ctr_nonce_reuse_repeats_keystream() -> None:
    key = b"N" * 16
    nonce = b"0" * 16
    first = block_modes.aes_ctr_crypt(fixtures.CTR_MESSAGE_ONE, key, nonce)
    second = block_modes.aes_ctr_crypt(fixtures.CTR_MESSAGE_TWO, key, nonce)
    length = min(len(first), len(second))
    assert block_modes.ctr_reuse_overlap(first, second) == bytes(
        left ^ right
        for left, right in zip(
            fixtures.CTR_MESSAGE_ONE[:length],
            fixtures.CTR_MESSAGE_TWO[:length],
            strict=True,
        )
    )
