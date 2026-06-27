import pytest

from feltcrypto.errors import PaddingError, ParseError
from feltcrypto.foundations import (
    base64_decode,
    base64_encode,
    byte_histogram,
    chunks,
    fixed_xor,
    hamming_distance,
    hex_decode,
    hex_encode,
    parse_bytes,
    pkcs7_pad,
    pkcs7_unpad,
    transpose_blocks,
)


def test_encoding_round_trips_and_explicit_parsing() -> None:
    data = b"cryptography operates on bytes"
    assert hex_decode(hex_encode(data)) == data
    assert base64_decode(base64_encode(data)) == data
    assert parse_bytes("hello", "text") == b"hello"
    assert parse_bytes("6869", "hex") == b"hi"


@pytest.mark.parametrize("value", ["not hex!", "0"])
def test_malformed_hex_fails_clearly(value: str) -> None:
    with pytest.raises(ParseError, match="hexadecimal"):
        hex_decode(value)


def test_malformed_base64_and_unknown_representation_fail() -> None:
    with pytest.raises(ParseError, match="Base64"):
        base64_decode("***")
    with pytest.raises(ParseError, match="representation"):
        parse_bytes("value", "guess")


def test_xor_hamming_chunks_transpose_and_histogram() -> None:
    assert (
        fixed_xor(
            bytes.fromhex("1c0111001f010100061a024b53535009181c"),
            bytes.fromhex("686974207468652062756c6c277320657965"),
        ).hex()
        == "746865206b696420646f6e277420706c6179"
    )
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37
    assert chunks(b"abcdefg", 3) == [b"abc", b"def", b"g"]
    assert transpose_blocks([b"abc", b"de"]) == [b"ad", b"be", b"c"]
    assert byte_histogram(b"abb") == {ord("a"): 1, ord("b"): 2}


def test_pkcs7_round_trip_and_strict_failures() -> None:
    for data in (b"", b"YELLOW SUBMARINE", b"hello"):
        assert pkcs7_unpad(pkcs7_pad(data, 16), 16) == data
    malformed = (
        b"",
        b"not aligned",
        b"A" * 15 + b"\x00",
        b"A" * 14 + b"\x02\x03",
        b"A" * 15 + b"\x11",
    )
    for value in malformed:
        with pytest.raises(PaddingError):
            pkcs7_unpad(value, 16)
