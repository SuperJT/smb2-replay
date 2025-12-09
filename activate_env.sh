#!/bin/bash
# Convenience script to activate the UV-managed virtual environment
# Usage: source activate_env.sh

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if UV is installed
if ! command -v uv &> /dev/null; then
    echo "❌ UV is not installed"
    echo ""
    echo "UV is recommended for faster dependency management (10-100x faster than pip)"
    echo "Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo ""
    echo "Or continue with pip (slower):"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -e ."
    return 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$SCRIPT_DIR/.venv" ]; then
    echo "Creating UV virtual environment..."
    uv venv "$SCRIPT_DIR/.venv"
fi

echo "Activating SMB2 Replay virtual environment (UV-managed)..."
source "$SCRIPT_DIR/.venv/bin/activate"

echo "✅ Virtual environment activated!"
echo "Python version: $(python --version)"
echo "UV version: $(uv --version)"
echo "Current directory: $(pwd)"
echo "Virtual environment: $VIRTUAL_ENV"
echo ""
echo "Quick start:"
echo "  Install basic:      uv sync"
echo "  Install dev-tools:  uv sync --extra dev-tools"
echo "  Install dev-full:   uv sync --all-extras"
echo "  Install API deps:   uv sync --extra api"
echo ""
echo "To run SMB Replay:    python -m smbreplay --help"
echo "To run tests:         pytest"
echo "To deactivate:        deactivate"
