"""Tests for repository JSON Schema documents."""

import json
from pathlib import Path

import pytest

from feltcrypto.registry import get_lesson, run_lesson
from feltcrypto.safe_api import decode_package, encode_package, encrypt, generate_key

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "Schema"


@pytest.mark.parametrize(
    "name",
    ["encrypted-package.schema.json", "demo-result.schema.json", "lesson.schema.json"],
)
def test_schema_files_are_valid_json(name: str) -> None:
    path = SCHEMA_DIR / name
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["$schema"]
    assert document["title"]


def test_demo_result_matches_documented_shape() -> None:
    result = run_lesson("break-caesar")
    document = result.as_dict()
    assert isinstance(document["lesson_id"], str)
    assert isinstance(document["success"], bool)
    assert document["educational_only"] is True


def test_lesson_metadata_matches_documented_shape() -> None:
    metadata = get_lesson("break-caesar").metadata()
    assert isinstance(metadata["summary"], dict)
    assert metadata["summary"]["safe_api_link"]


def test_encoded_package_matches_documented_shape() -> None:
    package = encrypt(generate_key(), b"schema check", b"meta")
    document = json.loads(encode_package(package))
    assert document["version"] == 1
    assert document["algorithm"] == "AES-256-GCM"
    assert decode_package(encode_package(package)).ciphertext == package.ciphertext
