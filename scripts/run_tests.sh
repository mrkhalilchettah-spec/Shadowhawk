#!/bin/bash
# ShadowHawk Platform - Test Runner Script
# Copyright (c) 2024 ShadowHawk Platform
# Licensed under the MIT License

set -e

echo "Running ShadowHawk Platform Tests..."

# Run unit tests
echo "Running unit tests..."
pytest tests/unit/ -v

# Run integration tests
echo "Running integration tests..."
pytest tests/integration/ -v

# Generate coverage report
echo "Generating coverage report..."
pytest --cov=src/shadowhawk --cov-report=html --cov-report=term-missing

echo "All tests completed successfully!"
