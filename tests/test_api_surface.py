"""Smoke and edge-case tests for every public API entry point."""

import importlib
import inspect
import pkgutil

import pytest

import feltcrypto
import feltcrypto.foundations as foundations
import feltcrypto.randomness as randomness
import feltcrypto.registry as registry
import feltcrypto.safe_api as safe_api
from feltcrypto import fixtures
from feltcrypto.weak import block_modes, classical, integrity, randomness_failures, sha1, xor


def _function_names(module: object) -> set[str]:
    return {
        name
        for name, value in inspect.getmembers(module, inspect.isfunction)
        if value.__module__ == module.__name__
    }


@pytest.mark.parametrize(
    "module_name",
    [
        "feltcrypto",
        "feltcrypto.cli",
        "feltcrypto.errors",
        "feltcrypto.fixtures",
        "feltcrypto.foundations",
        "feltcrypto.models",
        "feltcrypto.randomness",
        "feltcrypto.registry",
        "feltcrypto.safe_api",
        "feltcrypto.weak",
        "feltcrypto.weak.block_modes",
        "feltcrypto.weak.classical",
        "feltcrypto.weak.integrity",
        "feltcrypto.weak.randomness_failures",
        "feltcrypto.weak.sha1",
        "feltcrypto.weak.xor",
    ],
)
def test_package_modules_import_cleanly(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert module.__doc__


def test_all_feltcrypto_submodules_are_importable() -> None:
    prefix = f"{feltcrypto.__name__}."
    names = {name for _, name, _ in pkgutil.walk_packages(feltcrypto.__path__, prefix)}
    assert f"{prefix}weak.block_modes" in names
    for name in sorted(names):
        if name.endswith(".__main__"):
            continue
        importlib.import_module(name)


def test_foundations_encoding_helpers() -> None:
    data = b"api-surface"
    assert foundations.hex_encode(data) == data.hex()
    assert foundations.base64_encode(data) == "YXBpLXN1cmZhY2U="
    assert foundations.parse_bytes("YXBpLXN1cmZhY2U=", "base64") == data
    assert foundations.repeated_block_count(fixtures.ECB_PATTERN) > 0


def test_randomness_policy_helpers() -> None:
    generated = randomness.secure_bytes(16)
    assert len(generated) == 16
    rng = randomness.insecure_time_seeded_rng(123)
    assert rng.random() == randomness.insecure_time_seeded_rng(123).random()


def test_classical_private_scoring_helpers() -> None:
    assert classical._shift_char("Z", 1) == "A"
    assert classical._english_score_text("hello") == foundations.english_score(b"hello")


def test_randomness_failure_internals() -> None:
    source = randomness_failures.clone_mt19937([0] * 623 + [123456789])
    assert source.getrandbits(32) >= 0
    assert randomness_failures.untemper_mt19937(123456789) != 123456789


def test_sha1_left_rotate() -> None:
    assert sha1._left_rotate(0x80000000, 1) & 0xFFFFFFFF == 1


def test_safe_api_encrypted_package_defaults() -> None:
    package = safe_api.EncryptedPackage(b"\x00" * 12, b"ct")
    assert package.associated_data == b""


def test_registry_resolution_builder() -> None:
    resolutions = registry._safe_api_resolutions_for(registry.list_lessons())
    weak_count = len([lesson for lesson in registry.list_lessons() if lesson.is_weak])
    assert len(resolutions) == weak_count


def test_public_function_surfaces_are_non_empty() -> None:
    modules = (
        foundations,
        randomness,
        registry,
        safe_api,
        block_modes,
        classical,
        integrity,
        randomness_failures,
        sha1,
        xor,
    )
    for module in modules:
        assert _function_names(module)
