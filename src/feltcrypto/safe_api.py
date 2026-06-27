"""Small, boring authenticated-encryption API backed by ``cryptography``."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from feltcrypto.errors import AuthenticationError, ParseError
from feltcrypto.randomness import secure_bytes

PACKAGE_VERSION = 1
KEY_SIZE = 32
NONCE_SIZE = 12


@dataclass(frozen=True)
class EncryptedPackage:
    """Nonce, authenticated ciphertext/tag, and associated data."""

    nonce: bytes
    ciphertext: bytes
    associated_data: bytes = b""


def generate_key() -> bytes:
    return secure_bytes(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> EncryptedPackage:
    """Encrypt and authenticate, choosing a fresh nonce internally."""

    if len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")
    nonce = secure_bytes(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return EncryptedPackage(nonce, ciphertext, associated_data)


def decrypt(key: bytes, package: EncryptedPackage) -> bytes:
    """Verify before returning plaintext; authentication failures fail closed."""

    if len(key) != KEY_SIZE:
        raise ValueError("AES-256-GCM key must be exactly 32 bytes")
    if len(package.nonce) != NONCE_SIZE:
        raise AuthenticationError("invalid nonce; no plaintext was returned")
    try:
        return AESGCM(key).decrypt(
            package.nonce,
            package.ciphertext,
            package.associated_data,
        )
    except InvalidTag as exc:
        raise AuthenticationError(
            "authentication failed; package was altered or the key is wrong"
        ) from exc


def _encode_field(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_field(document: dict[str, Any], name: str) -> bytes:
    value = document.get(name)
    if not isinstance(value, str):
        raise ParseError(f"package field {name!r} must be Base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ParseError(f"package field {name!r} is not valid Base64") from exc


def encode_package(package: EncryptedPackage) -> str:
    document = {
        "version": PACKAGE_VERSION,
        "algorithm": "AES-256-GCM",
        "nonce": _encode_field(package.nonce),
        "ciphertext": _encode_field(package.ciphertext),
        "associated_data": _encode_field(package.associated_data),
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True)


def decode_package(encoded: str) -> EncryptedPackage:
    try:
        document = json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise ParseError("encrypted package is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ParseError("encrypted package must be a JSON object")
    if document.get("version") != PACKAGE_VERSION:
        raise ParseError(f"unsupported encrypted package version: {document.get('version')!r}")
    if document.get("algorithm") != "AES-256-GCM":
        raise ParseError("encrypted package algorithm must be AES-256-GCM")
    nonce = _decode_field(document, "nonce")
    if len(nonce) != NONCE_SIZE:
        raise ParseError(f"package field 'nonce' must decode to exactly {NONCE_SIZE} bytes")
    return EncryptedPackage(
        nonce=nonce,
        ciphertext=_decode_field(document, "ciphertext"),
        associated_data=_decode_field(document, "associated_data"),
    )
