# Developer convenience targets. Requires the dev extras:
#   pip install -e ".[dev]"
# On Windows, run these through Git Bash or invoke the commands directly.

.PHONY: install test lint format typecheck check

install:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy

check:
	ruff check .
	ruff format --check .
	mypy
	pytest --cov=feltcrypto --cov-fail-under=99
