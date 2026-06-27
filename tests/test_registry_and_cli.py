import json

import pytest

from feltcrypto import __version__
from feltcrypto.cli import main
from feltcrypto.errors import UnknownLessonError
from feltcrypto.registry import get_lesson, list_lessons, run_lesson


def test_registry_metadata_and_every_demo_succeeds() -> None:
    lesson_ids = {lesson.lesson_id for lesson in list_lessons()}
    assert "padding-oracle-demo" in lesson_ids
    assert "do-it-right" in lesson_ids
    for lesson in list_lessons():
        result = lesson.run_demo()
        assert result.success, lesson.lesson_id
        assert result.fixture_name == lesson.fixture_name
        assert result.local_fixture
        assert result.educational_only
        assert result.safe_api_reference == lesson.summary.safe_api_link
        assert all(lesson.summary.as_dict().values())
        if lesson.is_weak:
            assert result.not_for_real_use
            assert "local" in lesson.safety_notice.lower()
        else:
            assert not result.not_for_real_use


def test_unknown_lesson_fails_cleanly() -> None:
    with pytest.raises(UnknownLessonError, match="unknown lesson"):
        get_lesson("not-a-lesson")


def test_cli_list_and_direct_lesson_alias(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    listing = capsys.readouterr().out
    assert "break-caesar" in listing

    assert main(["break-caesar", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["lesson_id"] == "break-caesar"
    assert document["educational_only"] is True
    assert document["local_fixture"] is True
    assert document["not_for_real_use"] is True


def test_cli_show_text_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["show", "padding-oracle-demo"]) == 0
    text = capsys.readouterr().out
    assert "FAILURE:" in text
    assert "SAFE API LINK:" in text

    assert main(["show", "padding-oracle-demo", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["lesson_id"] == "padding-oracle-demo"
    assert document["explanation"]


def test_cli_run_prints_result_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "break-caesar"]) == 0
    output = capsys.readouterr().out
    assert "RECOVERED PLAINTEXT" in output
    assert "SAFE API" in output


def test_cli_run_all_executes_full_arc(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run-all", "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert len(results) == len(list_lessons())
    assert all(item["success"] for item in results)
    assert all(item["local_fixture"] for item in results)


def test_cli_run_all_aggregates_results(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = run_lesson("break-caesar")
    monkeypatch.setattr("feltcrypto.cli.run_all_lessons", lambda: [sample, sample])
    assert main(["run-all", "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert len(results) == 2
    assert all(item["success"] for item in results)


def test_cli_unknown_lesson_exits_with_code_two() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["show", "not-a-lesson"])
    assert excinfo.value.code == 2


def test_cli_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_do_it_right_maps_prior_failures_to_safe_api() -> None:
    result = run_lesson("do-it-right")
    resolutions = result.measurements["failure_to_safe_api"]
    assert isinstance(resolutions, list)
    assert len(resolutions) == 10
    assert result.safe_api_reference == "feltcrypto.safe_api.generate_key/encrypt/decrypt"


def test_weak_namespace_exposes_not_for_real_use_metadata() -> None:
    from feltcrypto import weak

    assert weak.NOT_FOR_REAL_USE is True
    for module in (
        weak.xor,
        weak.classical,
        weak.block_modes,
        weak.integrity,
        weak.randomness_failures,
        weak.sha1,
    ):
        assert module.__doc__ is not None
        assert "NOT SECURE" in module.__doc__ or "NOT CONSTANT-TIME" in module.__doc__


def test_cli_and_registry_are_in_sync() -> None:
    for lesson in list_lessons():
        assert run_lesson(lesson.lesson_id).lesson_id == lesson.lesson_id
