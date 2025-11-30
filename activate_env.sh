#!/bin/bash
# Convenience script to activate the virtual environment
# Usage: source activate_env.sh

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Activating SMB2 Replay virtual environment..."
source "$SCRIPT_DIR/venv/bin/activate"
echo "Virtual environment activated!"
echo "Python version: $(python --version)"
echo "Current directory: $(pwd)"
echo "Virtual environment: $VIRTUAL_ENV"
echo ""
echo "To run SMB Replay: python -m smbreplay --help"
echo "To run tests: python -m pytest"
echo "To deactivate: deactivate" 