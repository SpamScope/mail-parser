.PHONY: help clean clean-build clean-test test lint format check install build release
.DEFAULT_GOAL := help

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

help:  ## show this help message
	@python3 -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

install:  ## install dependencies using uv
	uv sync

clean-build:  ## remove build artifacts
	find . -type d -name "build" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +

clean-test:  ## remove test and coverage artifacts
	find . -type f -name "*.log" -delete
	find . -type f -name "coverage.xml" -delete
	find . -type f -name "junit.xml" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name "__pycache__" -exec rm -rf {} +

clean: clean-test clean-build  ## remove all artifacts

test:  ## run tests
	uv run pytest

lint:  ## run linting with ruff
	uv run ruff check .

format:  ## format code with ruff
	uv run ruff format .

check: lint test  ## run linting and tests

build: clean  ## build package
	uv build

pre-commit:  ## run pre-commit hooks
	uv run pre-commit run --all-files

release: build  ## build and upload to PyPI
	uv run twine upload dist/*
