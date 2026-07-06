"""Property-based hardening of the byte foundations 

The example-based tests check these invariants on a handful of hand-picked
inputs; Hypothesis fuzzes them across many generated inputs so an edge case we
did not think of would surface as a failing example.
"""

from hypothesis import given
from hypothesis import strategies as st

from feltcrypto.foundations import (
    base64_decode,
    base64_encode,
    fixed_xor,
    hamming_distance,
    hex_decode,
    hex_encode,
    pkcs7_pad,
    pkcs7_unpad,
)
from feltcrypto.weak.xor import single_byte_xor


@given(st.binary())
def test_hex_round_trips(data: bytes) -> None:
    assert hex_decode(hex_encode(data)) == data


@given(st.binary())
def test_base64_round_trips(data: bytes) -> None:
    assert base64_decode(base64_encode(data)) == data


@given(st.binary(max_size=128), st.integers(min_value=1, max_value=255))
def test_pkcs7_round_trips_for_any_block_size(data: bytes, block_size: int) -> None:
    assert pkcs7_unpad(pkcs7_pad(data, block_size), block_size) == data


@given(st.binary(), st.binary())
def test_fixed_xor_is_an_involution(left: bytes, right: bytes) -> None:
    length = min(len(left), len(right))
    a, b = left[:length], right[:length]
    assert fixed_xor(fixed_xor(a, b), b) == a


@given(st.binary(), st.integers(min_value=0, max_value=255))
def test_single_byte_xor_is_an_involution(data: bytes, key: int) -> None:
    assert single_byte_xor(single_byte_xor(data, key), key) == data


@given(st.binary())
def test_hamming_distance_to_self_is_zero(data: bytes) -> None:
    assert hamming_distance(data, data) == 0


@given(st.binary(), st.binary())
def test_hamming_distance_is_symmetric(left: bytes, right: bytes) -> None:
    length = min(len(left), len(right))
    a, b = left[:length], right[:length]
    assert hamming_distance(a, b) == hamming_distance(b, a)
