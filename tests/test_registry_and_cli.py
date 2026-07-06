"""Tests for the registry and cli modules."""

import json
import subprocess
import sys

import pytest

from feltcrypto import __version__
from feltcrypto.cli import main
from feltcrypto.errors import UnknownLessonError
from feltcrypto.models import DemoResult
from feltcrypto.registry import (
    _RESOLUTION_FAILURES,
    SAFE_API_RESOLUTIONS,
    get_lesson,
    list_lessons,
    run_all_lessons,
    run_lesson,
)


@pytest.fixture(scope="module")
def do_it_right_result() -> DemoResult:
    return run_lesson("do-it-right")


def test_run_all_lessons_yields_every_registry_entry() -> None:
    results = list(run_all_lessons())
    assert len(results) == len(list_lessons())
    lesson_ids = {lesson.lesson_id for lesson in list_lessons()}
    assert {result.lesson_id for result in results} == lesson_ids


def test_registry_metadata_for_every_lesson() -> None:
    lesson_ids = {lesson.lesson_id for lesson in list_lessons()}
    assert "padding-oracle-demo" in lesson_ids
    assert "do-it-right" in lesson_ids
    for lesson in list_lessons():
        assert lesson.fixture_name
        assert all(lesson.summary.as_dict().values())
        assert lesson.summary.safe_api_link
        if lesson.is_weak:
            assert "local" in lesson.safety_notice.lower()
        else:
            assert not lesson.is_weak


def test_every_lesson_demo_succeeds() -> None:
    for lesson in list_lessons():
        result = lesson.run_demo()
        assert result.success, lesson.lesson_id
        assert result.fixture_name == lesson.fixture_name
        assert result.local_fixture
        assert result.educational_only
        assert result.safe_api_reference == lesson.summary.safe_api_link
        if lesson.is_weak:
            assert result.not_for_real_use
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
    assert "DIAGNOSTICS:" in output
    assert "SAFE API" in output


def test_cli_run_all_exit_code_and_json(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = run_lesson("break-caesar")
    monkeypatch.setattr("feltcrypto.cli.run_all_lessons", lambda: [sample, sample])
    assert main(["run-all", "--json"]) == 0
    results = json.loads(capsys.readouterr().out)
    assert len(results) == 2
    assert all(item["success"] for item in results)


def test_cli_and_registry_are_in_sync() -> None:
    for lesson in list_lessons():
        assert get_lesson(lesson.lesson_id).lesson_id == lesson.lesson_id


def test_cli_unknown_lesson_returns_exit_code_three(capsys: pytest.CaptureFixture[str]) -> None:
    for arguments in (["show", "not-a-lesson"], ["run", "not-a-lesson"], ["not-a-lesson"]):
        assert main(arguments) == 3
        assert "error:" in capsys.readouterr().err


def test_cli_run_all_prints_summary(capsys: pytest.CaptureFixture[str]) -> None:
    sample = run_lesson("break-caesar")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("feltcrypto.cli.run_all_lessons", lambda: [sample, sample])
        assert main(["run-all"]) == 0
    output = capsys.readouterr().out
    assert "SUMMARY: 2/2 lessons succeeded" in output


def test_main_module_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "feltcrypto", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert __version__ in completed.stdout


def test_cli_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_safe_api_resolutions_cover_every_weak_lesson() -> None:
    weak_lessons = [lesson for lesson in list_lessons() if lesson.is_weak]
    weak_ids = {lesson.lesson_id for lesson in weak_lessons}
    resolution_ids = {item["prior_lesson"] for item in SAFE_API_RESOLUTIONS}
    assert resolution_ids == weak_ids
    assert set(_RESOLUTION_FAILURES) == weak_ids
    assert [item["prior_lesson"] for item in SAFE_API_RESOLUTIONS] == [
        lesson.lesson_id for lesson in weak_lessons
    ]


def test_safe_api_resolutions_match_lesson_links() -> None:
    lessons_by_id = {lesson.lesson_id: lesson for lesson in list_lessons()}
    for item in SAFE_API_RESOLUTIONS:
        lesson = lessons_by_id[item["prior_lesson"]]
        assert item["safe_api_link"] == lesson.summary.safe_api_link
        assert item["prevention"] == lesson.summary.safe_api_link


def test_do_it_right_demo_and_resolutions(do_it_right_result: DemoResult) -> None:
    result = do_it_right_result
    resolutions = result.measurements["failure_to_safe_api"]
    assert isinstance(resolutions, list)
    assert len(resolutions) == len([lesson for lesson in list_lessons() if lesson.is_weak])
    assert result.safe_api_reference == "feltcrypto.safe_api.generate_key/encrypt/decrypt"
    for item in resolutions:
        assert isinstance(item, dict)
        assert item["safe_api_link"] == item["prevention"]


def test_do_it_right_cli_output(
    do_it_right_result: DemoResult,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["do-it-right", "--json"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["lesson_id"] == "do-it-right"
    assert document["not_for_real_use"] is False
    assert document["educational_only"] is True

    assert main(["run", "do-it-right"]) == 0
    output = capsys.readouterr().out
    assert "RESOLUTIONS:" in output
    assert "break-caesar:" in output
    assert "feltcrypto.safe_api.encrypt/decrypt" in output
    assert "SAFETY:" not in output


def test_timing_lesson_uses_hmac_compare_digest_link() -> None:
    lesson = get_lesson("timing-attack-demo")
    assert lesson.summary.safe_api_link == "hmac.compare_digest"


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


def test_public_package_exports_documented_api() -> None:
    import feltcrypto

    for name in (
        "parse_bytes",
        "generate_key",
        "encrypt",
        "decrypt",
        "encode_package",
        "decode_package",
        "AuthenticationError",
        "PaddingError",
        "ParseError",
        "UnknownLessonError",
        "foundations",
        "safe_api",
    ):
        assert hasattr(feltcrypto, name)
