#!/bin/bash
# Quick start script for TFTP test harness
# Igor Konnov, 2025

set -e

echo "=== TFTP Test Harness Quick Start ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker."
    exit 1
fi
echo "✅ Docker found"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.9+."
    exit 1
fi
echo "✅ Python 3 found"

if ! command -v apalache-mc &> /dev/null; then
    if [ -z "$APALACHE_HOME" ]; then
        echo "❌ Apalache not found. Please install Apalache or set APALACHE_HOME."
        exit 1
    fi
fi
echo "✅ Apalache found"

# Verify test files
echo ""
echo "Verifying test files..."
python3 verify_files.py
if [ $? -ne 0 ]; then
    echo "Creating test files..."
    python3 verify_files.py --create
fi

# Check if Poetry is available
if command -v poetry &> /dev/null; then
    echo ""
    echo "Installing Python dependencies with Poetry..."
    poetry install
    
    echo ""
    echo "Building Docker image..."
    docker build -t tftp-test-harness:latest .
    
    echo ""
    echo "=== Setup Complete ==="
    echo ""
    echo "To run the test harness:"
    echo "  poetry run python harness.py"
    echo ""
    echo "Or with docker-compose:"
    echo "  docker-compose up -d"
    echo "  poetry run python harness.py"
    echo "  docker-compose down"
else
    echo ""
    echo "Poetry not found. Installing dependencies with pip..."
    pip3 install requests itf
    
    echo ""
    echo "Building Docker image..."
    docker build -t tftp-test-harness:latest .
    
    echo ""
    echo "=== Setup Complete ==="
    echo ""
    echo "To run the test harness:"
    echo "  python3 harness.py"
    echo ""
    echo "Or with docker-compose:"
    echo "  docker-compose up -d"
    echo "  python3 harness.py"
    echo "  docker-compose down"
fi
