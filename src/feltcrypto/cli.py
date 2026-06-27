"""Command-line interface for local academic demos."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from feltcrypto import __version__
from feltcrypto.errors import FeltCryptoError
from feltcrypto.models import DemoResult, JSONValue
from feltcrypto.registry import (
    SAFETY_NOTICE,
    get_lesson,
    list_lessons,
    run_all_lessons,
    run_lesson,
)


def _print_json(value: JSONValue) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _print_resolutions(measurements: dict[str, JSONValue]) -> None:
    resolutions = measurements.get("failure_to_safe_api")
    if not isinstance(resolutions, list):
        return
    print("RESOLUTIONS:")
    for item in resolutions:
        if not isinstance(item, dict):
            continue
        prior = item.get("prior_lesson", "?")
        failure = item.get("failure", "?")
        prevention = item.get("prevention", "?")
        print(f"  - {prior}: {failure} -> {prevention}")


def _print_result(result: DemoResult) -> None:
    print("=" * 72)
    print(f"LESSON: {result.lesson_id}")
    if result.not_for_real_use:
        print(f"SAFETY: {SAFETY_NOTICE}")
    print(f"FIXTURE: {result.fixture_name} (local={str(result.local_fixture).lower()})")
    print(f"SUCCESS: {str(result.success).lower()}")
    print(f"OBSERVATION: {result.observation}")
    if result.recovered_key is not None:
        print(f"RECOVERED KEY: {result.recovered_key}")
    if result.recovered_plaintext is not None:
        print(f"RECOVERED PLAINTEXT: {result.recovered_plaintext}")
    if result.diagnostics:
        print(f"DIAGNOSTICS: {json.dumps(result.diagnostics, sort_keys=True)}")
    if result.measurements:
        resolutions = result.measurements.get("failure_to_safe_api")
        other_measurements = {
            key: value for key, value in result.measurements.items() if key != "failure_to_safe_api"
        }
        if other_measurements:
            print(f"MEASUREMENTS: {json.dumps(other_measurements, sort_keys=True)}")
        if resolutions is not None:
            _print_resolutions(result.measurements)
    print(f"TAKEAWAY: {result.takeaway}")
    print(f"SAFE API: {result.safe_api_reference}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="feltcrypto",
        description="Academic crypto failure demos against bundled local fixtures only.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list lesson ids and titles")
    list_parser.add_argument("--json", action="store_true", dest="as_json")

    show_parser = subparsers.add_parser("show", help="show lesson metadata and explanation")
    show_parser.add_argument("lesson_id")
    show_parser.add_argument("--json", action="store_true", dest="as_json")

    run_parser = subparsers.add_parser("run", help="run one bundled local lesson")
    run_parser.add_argument("lesson_id")
    run_parser.add_argument("--json", action="store_true", dest="as_json")

    all_parser = subparsers.add_parser("run-all", help="run every bundled local lesson")
    all_parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    lesson_ids = {lesson.lesson_id for lesson in list_lessons()}
    if arguments and arguments[0] in lesson_ids:
        arguments.insert(0, "run")

    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        if args.command == "list":
            lessons = list_lessons()
            if args.as_json:
                _print_json([lesson.metadata() for lesson in lessons])
            else:
                for lesson in lessons:
                    label = "SAFE" if not lesson.is_weak else "WEAK / EDUCATIONAL"
                    print(f"{lesson.lesson_id:25} {label:18} {lesson.title}")
            return 0

        if args.command == "show":
            lesson = get_lesson(args.lesson_id)
            if args.as_json:
                metadata = lesson.metadata()
                metadata["explanation"] = lesson.explain()
                _print_json(metadata)
            else:
                print(f"{lesson.title} ({lesson.lesson_id})")
                print(f"Safety: {lesson.safety_notice}")
                print(f"Weak assumption: {lesson.weak_assumption}")
                print(f"How it works: {lesson.explain()}")
                print(f"FAILURE: {lesson.summary.failure}")
                print(f"CAUSE: {lesson.summary.cause}")
                print(f"CORRECT CONSTRUCTION: {lesson.summary.correct_construction}")
                print(f"SAFE API LINK: {lesson.summary.safe_api_link}")
            return 0

        if args.command == "run":
            result = run_lesson(args.lesson_id)
            if args.as_json:
                _print_json(result.as_dict())
            else:
                _print_result(result)
            return 0 if result.success else 1

        results = list(run_all_lessons())
        if args.as_json:
            _print_json([result.as_dict() for result in results])
        else:
            for result in results:
                _print_result(result)
        return 0 if all(result.success for result in results) else 1
    except (FeltCryptoError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
