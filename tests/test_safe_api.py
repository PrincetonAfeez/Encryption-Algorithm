import base64
import json

import pytest

from feltcrypto.errors import AuthenticationError, ParseError
from feltcrypto.safe_api import (
    EncryptedPackage,
    decode_package,
    decrypt,
    encode_package,
    encrypt,
    generate_key,
)


def test_safe_api_round_trip_and_serialization() -> None:
    key = generate_key()
    package = encrypt(key, b"secret bytes", b"record=7")
    assert decrypt(key, package) == b"secret bytes"
    assert decrypt(key, decode_package(encode_package(package))) == b"secret bytes"


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "associated_data"])
def test_safe_api_tampering_fails_closed(field: str) -> None:
    key = generate_key()
    package = encrypt(key, b"return no plaintext after tampering", b"local metadata")
    changed = bytearray(getattr(package, field))
    changed[0] ^= 1
    tampered = EncryptedPackage(
        nonce=bytes(changed) if field == "nonce" else package.nonce,
        ciphertext=bytes(changed) if field == "ciphertext" else package.ciphertext,
        associated_data=bytes(changed) if field == "associated_data" else package.associated_data,
    )
    with pytest.raises(AuthenticationError):
        decrypt(key, tampered)


def test_package_parser_rejects_malformed_input() -> None:
    with pytest.raises(ParseError, match="JSON"):
        decode_package("{")
    document = json.loads(encode_package(encrypt(generate_key(), b"x")))
    document["nonce"] = "***"
    with pytest.raises(ParseError, match="Base64"):
        decode_package(json.dumps(document))


def test_decode_package_rejects_wrong_version_and_algorithm() -> None:
    document = json.loads(encode_package(encrypt(generate_key(), b"x")))

    with pytest.raises(ParseError, match="version"):
        decode_package(json.dumps(dict(document, version=999)))

    with pytest.raises(ParseError, match="algorithm"):
        decode_package(json.dumps(dict(document, algorithm="ROT13")))


def test_decrypt_rejects_wrong_key() -> None:
    key = generate_key()
    package = encrypt(key, b"secret bytes", b"record=7")
    with pytest.raises(AuthenticationError, match="wrong"):
        decrypt(generate_key(), package)


def test_decrypt_rejects_wrong_key_length() -> None:
    key = generate_key()
    package = encrypt(key, b"secret bytes")
    with pytest.raises(ValueError, match="32 bytes"):
        decrypt(b"too-short", package)


def test_encrypt_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt(b"too-short", b"secret bytes")


def test_empty_plaintext_round_trip() -> None:
    key = generate_key()
    package = encrypt(key, b"")
    assert decrypt(key, package) == b""


def test_decode_package_rejects_missing_fields_and_wrong_nonce_length() -> None:
    document = json.loads(encode_package(encrypt(generate_key(), b"x")))

    for field in ("nonce", "ciphertext", "associated_data"):
        incomplete = dict(document)
        del incomplete[field]
        with pytest.raises(ParseError, match=field):
            decode_package(json.dumps(incomplete))

    document["nonce"] = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(ParseError, match="nonce"):
        decode_package(json.dumps(document))


def test_generate_key_uses_secure_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_secure_bytes(length: int) -> bytes:
        calls.append(length)
        return b"S" * length

    monkeypatch.setattr("feltcrypto.safe_api.secure_bytes", fake_secure_bytes)
    assert generate_key() == b"S" * 32
    assert calls == [32]
