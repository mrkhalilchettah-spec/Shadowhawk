# ShadowHawk Platform Makefile
# Copyright (c) 2024 ShadowHawk Team
# Licensed under the MIT License

.PHONY: help install test lint format type-check clean run-example

help:
	@echo "ShadowHawk Platform - Available Commands"
	@echo "========================================="
	@echo "make install      - Install dependencies"
	@echo "make test         - Run all tests"
	@echo "make test-cov     - Run tests with coverage"
	@echo "make lint         - Run linter (ruff)"
	@echo "make format       - Format code (black)"
	@echo "make type-check   - Run type checker (mypy)"
	@echo "make clean        - Clean build artifacts"
	@echo "make run-example  - Run basic usage example"

install:
	poetry install

test:
	poetry run pytest -v

test-cov:
	poetry run pytest --cov=shadowhawk --cov-report=html --cov-report=term

lint:
	poetry run ruff check src/ tests/

format:
	poetry run black src/ tests/ examples/

type-check:
	poetry run mypy src/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf htmlcov/ .coverage

run-example:
	poetry run python examples/basic_usage.py

all: install test lint type-check
