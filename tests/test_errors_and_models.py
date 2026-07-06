"""Tests for exception types and shared data models."""

from feltcrypto.errors import (
    AuthenticationError,
    FeltCryptoError,
    PaddingError,
    ParseError,
    UnknownLessonError,
)
from feltcrypto.models import DemoResult, LessonSummary
from feltcrypto.registry import get_lesson


def test_exception_hierarchy() -> None:
    assert issubclass(ParseError, FeltCryptoError)
    assert issubclass(ParseError, ValueError)
    assert issubclass(PaddingError, FeltCryptoError)
    assert issubclass(PaddingError, ValueError)
    assert issubclass(UnknownLessonError, FeltCryptoError)
    assert issubclass(UnknownLessonError, KeyError)
    assert issubclass(AuthenticationError, FeltCryptoError)
    assert not issubclass(AuthenticationError, ValueError)


def test_lesson_summary_as_dict() -> None:
    summary = LessonSummary("f", "c", "fix", "link")
    assert summary.as_dict() == {
        "failure": "f",
        "cause": "c",
        "correct_construction": "fix",
        "safe_api_link": "link",
    }


def test_demo_result_as_dict_includes_defaults() -> None:
    result = DemoResult(
        lesson_id="demo",
        concepts=("bytes",),
        fixture_name="local",
        success=True,
        observation="observed",
        takeaway="learned",
        safe_api_reference="feltcrypto.safe_api.encrypt/decrypt",
    )
    document = result.as_dict()
    assert document["recovered_key"] is None
    assert document["recovered_plaintext"] is None
    assert document["measurements"] == {}
    assert document["diagnostics"] == {}
    assert document["educational_only"] is True
    assert document["local_fixture"] is True
    assert document["not_for_real_use"] is True


def test_lesson_explain_metadata_and_weak_flag() -> None:
    weak = get_lesson("break-caesar")
    assert weak.explain()
    weak_meta = weak.metadata()
    assert weak_meta["lesson_id"] == "break-caesar"
    assert weak_meta["not_for_real_use"] is True
    assert weak_meta["concepts"] == list(weak.concepts)

    safe = get_lesson("do-it-right")
    assert safe.metadata()["not_for_real_use"] is False
