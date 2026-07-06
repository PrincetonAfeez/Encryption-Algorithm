"""Tests for the integrity and randomness modules."""

import hashlib
import random

import pytest

from feltcrypto.weak import integrity, randomness_failures
from feltcrypto.weak.sha1 import educational_sha1


def test_educational_sha1_matches_standard_digest() -> None:
    for message in (b"", b"abc", b"a" * 1000):
        assert educational_sha1(message) == hashlib.sha1(message).digest()


def test_length_extension_succeeds_but_hmac_rejects_forgery() -> None:
    key = b"local-secret"
    message = b"action=view"
    suffix = b"&admin=true"
    tag = integrity.naive_prefix_mac(key, message)
    forged_message, forged_tag = integrity.forge_prefix_mac(message, tag, suffix, len(key))
    assert integrity.verify_naive_prefix_mac(key, forged_message, forged_tag)

    genuine_hmac = integrity.hmac_sha256(key, message)
    assert integrity.verify_hmac_sha256(key, message, genuine_hmac)
    # HMAC has no length-extension shortcut: the tag for the original message
    # does not authenticate message || suffix, and the rejection is by value
    # (both tags are the same length), not a tag-size mismatch.
    extended = integrity.hmac_sha256(key, message + suffix)
    assert len(extended) == len(genuine_hmac)
    assert not integrity.verify_hmac_sha256(key, message + suffix, genuine_hmac)


def test_timing_demo_measures_early_return_and_constant_compare() -> None:
    secret = b"local-tag"
    measurement = integrity.measure_timing_leak(secret, trials=20, work_factor=300)
    assert measurement.full_match_median_ns > measurement.first_byte_mismatch_median_ns
    assert integrity.constant_time_compare(secret, secret)
    assert not integrity.constant_time_compare(secret, b"other-tag")
    with pytest.raises(ValueError, match="non-empty"):
        integrity.measure_timing_leak(b"")


def test_time_seed_is_recovered_inside_small_window() -> None:
    seed = 1_700_000_123
    token = randomness_failures.generate_time_seeded_token(seed)
    assert randomness_failures.recover_time_seed(token, seed + 5, 10) == seed
    assert randomness_failures.recover_time_seed(token, seed + 500, 1) is None


def test_clone_mt19937_requires_exactly_624_outputs() -> None:
    with pytest.raises(ValueError, match="624"):
        randomness_failures.clone_mt19937([0] * 623)


def test_insecure_compare_length_mismatch() -> None:
    assert not integrity.insecure_compare(b"abc", b"ab")


def test_forge_prefix_mac_rejects_non_positive_key_length() -> None:
    with pytest.raises(ValueError, match="positive"):
        integrity.forge_prefix_mac(b"m", b"t", b"s", 0)


def test_naive_prefix_mac_verify_round_trip() -> None:
    key = b"demo-key"
    message = b"local message"
    tag = integrity.naive_prefix_mac(key, message)
    assert integrity.verify_naive_prefix_mac(key, message, tag)
    assert not integrity.verify_naive_prefix_mac(key, message + b"tamper", tag)


def test_mt19937_clone_predicts_future_outputs() -> None:
    source = random.Random(12345)
    observations = [source.getrandbits(32) for _ in range(624)]
    clone = randomness_failures.clone_mt19937(observations)
    assert [clone.getrandbits(32) for _ in range(20)] == [source.getrandbits(32) for _ in range(20)]
