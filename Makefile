.PHONY: install install-dev test lint format clean build help

help:
	@echo "py-vuln-scout - Makefile commands:"
	@echo "  make install      - Install package in editable mode"
	@echo "  make install-dev  - Install with dev dependencies"
	@echo "  make test         - Run test suite with coverage"
	@echo "  make lint         - Run linters (ruff, mypy)"
	@echo "  make format       - Format code with black and ruff"
	@echo "  make clean        - Remove build artifacts and cache"
	@echo "  make build        - Build distribution packages"
	@echo "  make pre-commit   - Install pre-commit hooks"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check src/ tests/
	mypy src/

format:
	black src/ tests/
	ruff check --fix src/ tests/

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

pre-commit:
	pre-commit install
