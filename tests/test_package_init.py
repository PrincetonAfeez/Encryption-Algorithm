"""Package metadata and import surface tests."""

import importlib
from importlib.metadata import PackageNotFoundError, version

import pytest

import feltcrypto


def test_version_matches_project_metadata() -> None:
    assert feltcrypto.__version__ == version("feltcrypto")


def test_version_fallback_when_metadata_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_name: str) -> str:
        raise PackageNotFoundError()

    monkeypatch.setattr("importlib.metadata.version", missing)
    reloaded = importlib.reload(feltcrypto)
    assert reloaded.__version__ == "0.1.6"
    importlib.reload(feltcrypto)


def test_all_exports_are_importable() -> None:
    for name in feltcrypto.__all__:
        assert hasattr(feltcrypto, name)
