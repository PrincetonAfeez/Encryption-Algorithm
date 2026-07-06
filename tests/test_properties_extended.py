"""Additional property-based coverage for foundations helpers."""

from hypothesis import given
from hypothesis import strategies as st

from feltcrypto.foundations import (
    byte_histogram,
    chunks,
    english_score,
    index_of_coincidence,
    parse_bytes,
    transpose_blocks,
)


@given(st.text(min_size=1, max_size=40, alphabet=st.characters(codec="ascii")))
def test_parse_bytes_text_round_trips(value: str) -> None:
    assert parse_bytes(value, "text") == value.encode("utf-8")


@given(st.binary(min_size=1, max_size=64), st.integers(min_value=1, max_value=32))
def test_chunks_cover_input(data: bytes, size: int) -> None:
    parts = chunks(data, size)
    assert b"".join(parts) == data
    assert all(len(part) <= size for part in parts)


@given(st.lists(st.binary(min_size=0, max_size=8), min_size=1, max_size=6))
def test_transpose_then_untranspose_preserves_total_bytes(blocks: list[bytes]) -> None:
    columns = transpose_blocks(blocks)
    assert sum(len(block) for block in blocks) == sum(len(column) for column in columns)


@given(st.binary(max_size=32))
def test_byte_histogram_counts_are_non_negative(data: bytes) -> None:
    histogram = byte_histogram(data)
    assert all(count >= 0 for count in histogram.values())
    assert sum(histogram.values()) == len(data)


@given(st.binary(max_size=64))
def test_english_score_is_finite_for_non_empty_ascii(data: bytes) -> None:
    if data:
        assert english_score(data) != float("-inf")


@given(st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=2, max_size=40))
def test_index_of_coincidence_is_between_zero_and_one(text: str) -> None:
    value = index_of_coincidence(text)
    assert 0.0 <= value <= 1.0
