"""Exhaustive CLI and internal output helper tests."""

import json

import pytest

from feltcrypto.cli import (
    _print_resolutions,
    _print_result,
    build_parser,
    main,
)
from feltcrypto.models import DemoResult
from feltcrypto.registry import list_lessons, run_lesson


def test_build_parser_exposes_subcommands() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
    assert parser.parse_args(["list"]).command == "list"
    assert parser.parse_args(["show", "break-caesar"]).lesson_id == "break-caesar"
    assert parser.parse_args(["run", "break-caesar"]).command == "run"
    assert parser.parse_args(["run-all"]).command == "run-all"


def test_cli_list_json_includes_every_lesson(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list", "--json"]) == 0
    lessons = json.loads(capsys.readouterr().out)
    assert len(lessons) == 15
    lesson_ids = {lesson.lesson_id for lesson in list_lessons()}
    assert {item["lesson_id"] for item in lessons} == lesson_ids


def test_cli_list_text_marks_safe_lesson(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    output = capsys.readouterr().out
    assert "do-it-right" in output
    assert "SAFE" in output
    assert "WEAK / EDUCATIONAL" in output


def test_cli_run_failure_returns_exit_code_one(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    failed = run_lesson("break-caesar")
    failed.success = False
    monkeypatch.setattr("feltcrypto.cli.run_lesson", lambda _lesson_id: failed)
    assert main(["run", "break-caesar"]) == 1
    assert "SUCCESS: false" in capsys.readouterr().out


def test_cli_run_all_failure_summary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ok = run_lesson("break-caesar")
    bad = run_lesson("break-caesar")
    bad.success = False
    monkeypatch.setattr("feltcrypto.cli.run_all_lessons", lambda: [ok, bad])
    assert main(["run-all"]) == 1
    assert "SUMMARY: 1/2 lessons succeeded" in capsys.readouterr().out


def test_cli_value_error_returns_exit_code_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_lesson_id: str) -> DemoResult:
        raise ValueError("simulated lesson failure")

    monkeypatch.setattr("feltcrypto.cli.run_lesson", boom)
    assert main(["run", "break-caesar"]) == 3
    assert "error: simulated lesson failure" in capsys.readouterr().err


def test_cli_usage_error_exits_with_code_two() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["run"])
    assert excinfo.value.code == 2


def test_cli_unknown_option_exits_with_code_two() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["list", "--not-an-option"])
    assert excinfo.value.code == 2


def test_print_resolutions_ignores_invalid_entries(capsys: pytest.CaptureFixture[str]) -> None:
    _print_resolutions({"failure_to_safe_api": "not-a-list"})
    assert capsys.readouterr().out == ""

    _print_resolutions({"failure_to_safe_api": ["not-a-dict", {"prior_lesson": "x"}]})
    output = capsys.readouterr().out
    assert "RESOLUTIONS:" in output
    assert "x:" in output


def test_print_result_formats_optional_fields(capsys: pytest.CaptureFixture[str]) -> None:
    result = DemoResult(
        lesson_id="demo",
        concepts=("demo",),
        fixture_name="fixture-local",
        success=True,
        observation="observation text",
        takeaway="takeaway text",
        safe_api_reference="feltcrypto.safe_api.encrypt/decrypt",
        recovered_key="KEY",
        recovered_plaintext="PLAINTEXT",
        diagnostics={"alpha": 1},
        measurements={
            "beta": 2,
            "failure_to_safe_api": [{"prior_lesson": "a", "failure": "f", "safe_api_link": "l"}],
        },
        not_for_real_use=True,
    )
    _print_result(result)
    output = capsys.readouterr().out
    assert "RECOVERED KEY: KEY" in output
    assert "RECOVERED PLAINTEXT: PLAINTEXT" in output
    assert "DIAGNOSTICS:" in output
    assert "MEASUREMENTS:" in output
    assert "RESOLUTIONS:" in output
    assert "SAFETY:" in output


def test_print_result_omits_safety_for_safe_lesson(capsys: pytest.CaptureFixture[str]) -> None:
    result = run_lesson("do-it-right")
    _print_result(result)
    assert "SAFETY:" not in capsys.readouterr().out
