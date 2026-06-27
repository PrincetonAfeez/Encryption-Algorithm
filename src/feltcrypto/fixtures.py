"""Bundled, deterministic toy data. Attack demos never target external input."""

from __future__ import annotations

LONG_ENGLISH = (
    "Cryptography is less about making text look mysterious and more about preserving "
    "carefully stated guarantees. A message can appear thoroughly scrambled while still "
    "leaking its structure, its repeated phrases, or even its key. This teaching library "
    "uses deliberately weak local examples so that each failure can be observed safely. "
    "When a key is reused, when integrity is omitted, or when an error message reveals one "
    "small bit of information, an attacker can combine those clues into a complete break. "
    "The durable lesson is pleasantly boring: use authenticated encryption from a vetted "
    "library, generate secrets with a cryptographic random source, and keep the public API "
    "too small to express dangerous choices. "
) * 4

CAESAR_PLAINTEXT = "Looks scrambled is not security. Letter frequencies survive a shift cipher."
CAESAR_KEY = 11

VIGENERE_PLAINTEXT = LONG_ENGLISH
VIGENERE_KEY = "ORANGE"

REPEATING_XOR_PLAINTEXT = LONG_ENGLISH.encode("ascii")
REPEATING_XOR_KEY = b"ICE"

SINGLE_BYTE_XOR_PLAINTEXT = b"single byte xor is a substitution cipher over bytes"
SINGLE_BYTE_XOR_KEY = 77

OTP_MESSAGE_ONE = b"meet me at the library at seven tonight."
OTP_SECURE_PAD = bytes((index * 97 + 13) % 256 for index in range(len(OTP_MESSAGE_ONE)))
OTP_MESSAGE_TWO = b"send me the revised chapter at nine tonight."
OTP_CRIB = b" the "

ECB_PATTERN = b"YELLOW SUBMARINE" * 8

CBC_ADMIN_PLAINTEXT = b"comment=toy-demo;admin=0;scope=local-only"
CBC_ORACLE_PLAINTEXT = b"Padding oracles turn one leaked bit into recovered local plaintext."

CTR_MESSAGE_ONE = b"nonce reuse makes stream ciphers repeat their keystream"
CTR_MESSAGE_TWO = b"local demos make dangerous invariants visible and memorable"

TIMING_SECRET = b"local-demo-tag"

SUBSTITUTION_PLAINTEXT = (
    "this teaching library shows that simple substitution preserves repeated letter "
    "patterns and familiar word shapes"
)
SUBSTITUTION_ALPHABET = "QWERTYUIOPASDFGHJKLZXCVBNM"
SUBSTITUTION_VOCABULARY = (
    "this",
    "that",
    "teaching",
    "learning",
    "library",
    "cipher",
    "shows",
    "proves",
    "simple",
    "strong",
    "substitution",
    "encryption",
    "preserves",
    "destroys",
    "repeated",
    "hidden",
    "letter",
    "number",
    "patterns",
    "secrets",
    "and",
    "but",
    "familiar",
    "unknown",
    "word",
    "byte",
    "shapes",
    "values",
)
