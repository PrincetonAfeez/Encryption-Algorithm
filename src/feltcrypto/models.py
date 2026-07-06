"""Shared typed models for lessons and their results """

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import TypeAlias, cast

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


@dataclass(frozen=True)
class LessonSummary:
    """The four conclusions every weak lesson must make explicit."""

    failure: str
    cause: str
    correct_construction: str
    safe_api_link: str

    def as_dict(self) -> dict[str, JSONValue]:
        return asdict(self)


@dataclass
class DemoResult:
    """A consistent, JSON-serializable result from a local lesson demo."""

    lesson_id: str
    concepts: tuple[str, ...]
    fixture_name: str
    success: bool
    observation: str
    takeaway: str
    safe_api_reference: str
    recovered_key: str | None = None
    recovered_plaintext: str | None = None
    measurements: dict[str, JSONValue] = field(default_factory=dict)
    diagnostics: dict[str, JSONValue] = field(default_factory=dict)
    educational_only: bool = True
    local_fixture: bool = True
    not_for_real_use: bool = True

    def as_dict(self) -> dict[str, JSONValue]:
        payload = cast(dict[str, JSONValue], asdict(self))
        payload["concepts"] = list(self.concepts)
        return payload


DemoRunner: TypeAlias = Callable[[], DemoResult]


@dataclass(frozen=True)
class Lesson:
    """Metadata and behavior for one self-contained lesson."""

    lesson_id: str
    title: str
    concepts: tuple[str, ...]
    fixture_name: str
    weak_assumption: str
    safety_notice: str
    summary: LessonSummary
    run_demo: DemoRunner
    explanation: str
    is_weak: bool = True

    def explain(self) -> str:
        return self.explanation

    def metadata(self) -> dict[str, JSONValue]:
        return {
            "lesson_id": self.lesson_id,
            "title": self.title,
            "concepts": list(self.concepts),
            "fixture_name": self.fixture_name,
            "weak_assumption": self.weak_assumption,
            "educational_only": True,
            "local_fixture": True,
            "not_for_real_use": self.is_weak,
            "safety_notice": self.safety_notice,
            "summary": self.summary.as_dict(),
        }
