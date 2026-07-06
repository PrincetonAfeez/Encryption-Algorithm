# Developer convenience targets. Requires the dev extras:
#   pip install -e ".[dev]"
# On Windows, run these through Git Bash or invoke the commands directly.

.PHONY: install test lint format typecheck check lock

install:
	pip install --require-hashes -r requirements-dev.txt
	pip install -e . --no-deps

lock:
	pip-compile --generate-hashes --output-file=requirements.txt requirements.in
	pip-compile --generate-hashes --output-file=requirements-dev.txt requirements-dev.in

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
