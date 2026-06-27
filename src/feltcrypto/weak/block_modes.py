"""Deliberately misused AES modes for local teaching fixtures.

AES comes from ``cryptography``. The weaknesses here are in the surrounding
construction. NOT SECURE. NEVER USE FOR REAL PROTECTION.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from feltcrypto.errors import PaddingError
from feltcrypto.foundations import (
    fixed_xor,
    pkcs7_pad,
    pkcs7_unpad,
    repeated_block_count,
)

AES_BLOCK_SIZE = 16
PaddingOracle = Callable[[bytes, bytes], bool]


def _validate_aes_key(key: bytes) -> None:
    if len(key) not in {16, 24, 32}:
        raise ValueError("AES key must be 16, 24, or 32 bytes")


def aes_ecb_encrypt(plaintext: bytes, key: bytes, *, pad: bool = True) -> bytes:
    _validate_aes_key(key)
    data = pkcs7_pad(plaintext, AES_BLOCK_SIZE) if pad else plaintext
    if len(data) % AES_BLOCK_SIZE:
        raise ValueError("ECB plaintext must be block aligned when padding is disabled")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ecb_decrypt(ciphertext: bytes, key: bytes, *, unpad: bool = True) -> bytes:
    _validate_aes_key(key)
    if len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError("ECB ciphertext must be block aligned")
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(plaintext, AES_BLOCK_SIZE) if unpad else plaintext


def detect_ecb(ciphertext: bytes) -> bool:
    """Flag ECB mode by the presence of any repeated ciphertext block."""

    return repeated_block_count(ciphertext, AES_BLOCK_SIZE) > 0


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    _validate_aes_key(key)
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE)
    return encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    _validate_aes_key(key)
    if len(iv) != AES_BLOCK_SIZE or not ciphertext or len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError("CBC requires a 16-byte IV and block-aligned ciphertext")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded, AES_BLOCK_SIZE)


def cbc_bit_flip(
    ciphertext: bytes,
    iv: bytes,
    plaintext_offset: int,
    known: bytes,
    desired: bytes,
) -> tuple[bytes, bytes]:
    """Modify the preceding block so known local plaintext changes predictably."""

    if len(known) != len(desired):
        raise ValueError("known and desired fragments must have equal length")
    if plaintext_offset < 0:
        raise ValueError("plaintext offset must not be negative")
    if plaintext_offset + len(known) > len(ciphertext):
        raise ValueError("target fragment extends past the ciphertext")

    modified_iv = bytearray(iv)
    modified_ciphertext = bytearray(ciphertext)
    for index, (old, new) in enumerate(zip(known, desired, strict=True)):
        absolute = plaintext_offset + index
        block_index, within_block = divmod(absolute, AES_BLOCK_SIZE)
        delta = old ^ new
        if block_index == 0:
            modified_iv[within_block] ^= delta
        else:
            modified_ciphertext[(block_index - 1) * AES_BLOCK_SIZE + within_block] ^= delta
    return bytes(modified_ciphertext), bytes(modified_iv)


@dataclass(frozen=True)
class LocalPaddingOracle:
    """A deliberately vulnerable one-bit interface around a private local key."""

    key: bytes

    def __post_init__(self) -> None:
        _validate_aes_key(self.key)

    def valid_padding(self, iv: bytes, ciphertext: bytes) -> bool:
        try:
            aes_cbc_decrypt(ciphertext, self.key, iv)
        except (PaddingError, ValueError):
            return False
        return True


def padding_oracle_attack(iv: bytes, ciphertext: bytes, oracle: PaddingOracle) -> tuple[bytes, int]:
    """Recover local CBC plaintext using only a valid/invalid padding bit."""

    if len(iv) != AES_BLOCK_SIZE or not ciphertext or len(ciphertext) % AES_BLOCK_SIZE:
        raise ValueError("oracle attack fixture must use a 16-byte IV and aligned ciphertext")

    blocks = [
        ciphertext[index : index + AES_BLOCK_SIZE]
        for index in range(0, len(ciphertext), AES_BLOCK_SIZE)
    ]
    previous_blocks = [iv, *blocks[:-1]]
    recovered = bytearray()
    queries = 0

    for previous, target in zip(previous_blocks, blocks, strict=True):
        intermediate = bytearray(AES_BLOCK_SIZE)
        plaintext_block = bytearray(AES_BLOCK_SIZE)
        crafted = bytearray(AES_BLOCK_SIZE)

        for index in range(AES_BLOCK_SIZE - 1, -1, -1):
            padding_value = AES_BLOCK_SIZE - index
            for suffix_index in range(index + 1, AES_BLOCK_SIZE):
                crafted[suffix_index] = intermediate[suffix_index] ^ padding_value

            valid_candidates: list[int] = []
            for candidate in range(256):
                crafted[index] = candidate
                queries += 1
                if oracle(bytes(crafted), target):
                    if padding_value == 1 and index > 0:
                        probe = bytearray(crafted)
                        probe[index - 1] ^= 1
                        queries += 1
                        if not oracle(bytes(probe), target):
                            continue
                    valid_candidates.append(candidate)

            if not valid_candidates:
                raise RuntimeError("padding oracle failed to find a valid byte")
            chosen = valid_candidates[0]
            intermediate[index] = chosen ^ padding_value
            plaintext_block[index] = intermediate[index] ^ previous[index]

        recovered.extend(plaintext_block)

    return pkcs7_unpad(bytes(recovered), AES_BLOCK_SIZE), queries


def aes_ctr_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    _validate_aes_key(key)
    if len(nonce) != AES_BLOCK_SIZE:
        raise ValueError("this CTR demo uses a 16-byte initial counter value")
    transform = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return transform.update(data) + transform.finalize()


def ctr_reuse_overlap(ciphertext_one: bytes, ciphertext_two: bytes) -> bytes:
    length = min(len(ciphertext_one), len(ciphertext_two))
    return fixed_xor(ciphertext_one[:length], ciphertext_two[:length])
