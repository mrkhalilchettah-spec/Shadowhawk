#!/bin/bash
# ShadowHawk Platform - Quick Start Script
# Copyright (c) 2024 ShadowHawk Platform
# Licensed under the MIT License

set -e

echo "=== ShadowHawk Platform Quick Start ==="
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Copy environment file
if [ ! -f ".env" ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your configuration!"
fi

# Run basic tests
echo ""
echo "Running basic tests..."
pytest tests/unit/ -v --tb=short || echo "Some tests may fail without full setup"

echo ""
echo "=== Quick Start Complete! ==="
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Run: source venv/bin/activate"
echo "3. Run: uvicorn src.shadowhawk.api.main:app --reload"
echo "4. Visit: http://localhost:8000/docs"
echo ""
