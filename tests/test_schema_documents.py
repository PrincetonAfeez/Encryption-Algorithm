"""Tests for repository JSON Schema documents."""

import base64
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from feltcrypto.registry import get_lesson, run_lesson
from feltcrypto.safe_api import encode_package, encrypt, generate_key

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "Schema"


def load_schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "name",
    ["encrypted-package.schema.json", "demo-result.schema.json", "lesson.schema.json"],
)
def test_schema_files_are_valid_json(name: str) -> None:
    document = load_schema(name)
    assert document["$schema"]
    assert document["title"]


def test_encrypted_package_schema_accepts_encoded_package() -> None:
    schema = load_schema("encrypted-package.schema.json")
    document = json.loads(encode_package(encrypt(generate_key(), b"schema check", b"meta")))
    Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize(
    "nonce",
    [
        "",
        base64.b64encode(b"short").decode("ascii"),
        base64.b64encode(b"x" * 13).decode("ascii"),
        "***",
    ],
)
def test_encrypted_package_schema_rejects_invalid_nonce(nonce: str) -> None:
    schema = load_schema("encrypted-package.schema.json")
    document = json.loads(encode_package(encrypt(generate_key(), b"x")))
    document["nonce"] = nonce
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)


def test_demo_result_schema_accepts_lesson_output() -> None:
    schema = load_schema("demo-result.schema.json")
    Draft202012Validator(schema).validate(run_lesson("break-caesar").as_dict())


def test_demo_result_schema_rejects_unknown_fields() -> None:
    schema = load_schema("demo-result.schema.json")
    document = run_lesson("break-caesar").as_dict()
    document["unexpected"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)


def test_demo_result_schema_rejects_missing_required_field() -> None:
    schema = load_schema("demo-result.schema.json")
    document = run_lesson("break-caesar").as_dict()
    del document["lesson_id"]
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)


def test_lesson_schema_accepts_metadata() -> None:
    schema = load_schema("lesson.schema.json")
    Draft202012Validator(schema).validate(get_lesson("break-caesar").metadata())


def test_lesson_schema_accepts_show_json_shape() -> None:
    schema = load_schema("lesson.schema.json")
    lesson = get_lesson("break-caesar")
    metadata = lesson.metadata()
    metadata["explanation"] = lesson.explain()
    Draft202012Validator(schema).validate(metadata)


def test_lesson_schema_rejects_unknown_fields() -> None:
    schema = load_schema("lesson.schema.json")
    document = get_lesson("break-caesar").metadata()
    document["unexpected"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)


def test_lesson_schema_rejects_missing_required_field() -> None:
    schema = load_schema("lesson.schema.json")
    document = get_lesson("break-caesar").metadata()
    del document["title"]
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)
