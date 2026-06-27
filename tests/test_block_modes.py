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


@pytest.mark.parametrize(
    ("operation", "args"),
    [
        (
            "ecb_encrypt",
            (
                b"hello",
                b"bad-key",
            ),
        ),
        (
            "ecb_decrypt",
            (
                b"x" * 16,
                b"bad-key",
            ),
        ),
        ("cbc_encrypt", (b"hello", b"bad-key", b"I" * 16)),
        ("cbc_decrypt", (b"x" * 16, b"bad-key", b"I" * 16)),
        ("ctr_crypt", (b"hello", b"bad-key", b"0" * 16)),
    ],
)
def test_block_modes_reject_invalid_aes_key(operation: str, args: tuple[bytes, ...]) -> None:
    with pytest.raises(ValueError, match="AES key"):
        getattr(block_modes, f"aes_{operation}")(*args)


def test_ecb_rejects_unaligned_input_when_padding_disabled() -> None:
    key = b"K" * 16
    with pytest.raises(ValueError, match="block aligned"):
        block_modes.aes_ecb_encrypt(b"not aligned", key, pad=False)
    with pytest.raises(ValueError, match="block aligned"):
        block_modes.aes_ecb_decrypt(b"short", key, unpad=False)


def test_cbc_rejects_bad_iv_and_ciphertext() -> None:
    key = b"C" * 16
    with pytest.raises(ValueError, match="IV"):
        block_modes.aes_cbc_encrypt(b"hello", key, b"short")
    with pytest.raises(ValueError, match="block-aligned"):
        block_modes.aes_cbc_decrypt(b"short", key, b"I" * 16)


def test_ctr_rejects_wrong_counter_size() -> None:
    key = b"N" * 16
    with pytest.raises(ValueError, match="16-byte"):
        block_modes.aes_ctr_crypt(b"hello", key, b"short")


def test_cbc_bit_flip_rejects_mismatched_fragments_and_negative_offset() -> None:
    key = b"C" * 16
    iv = b"V" * 16
    ciphertext = block_modes.aes_cbc_encrypt(b"short message", key, iv)
    with pytest.raises(ValueError, match="equal length"):
        block_modes.cbc_bit_flip(ciphertext, iv, 0, b"ab", b"a")
    with pytest.raises(ValueError, match="negative"):
        block_modes.cbc_bit_flip(ciphertext, iv, -1, b"x", b"y")


def test_padding_oracle_attack_rejects_bad_fixture() -> None:
    with pytest.raises(ValueError, match="oracle attack fixture"):
        block_modes.padding_oracle_attack(b"short", b"data", lambda _iv, _ct: False)
