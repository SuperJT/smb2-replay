#!/bin/bash
# Quick setup script for UV-based development
# This script installs UV, creates a virtual environment, and installs dependencies

set -e  # Exit on error

echo "🚀 SMB2 Replay UV Setup"
echo "======================="
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Install UV if not present
if ! command -v uv &> /dev/null; then
    echo "📦 UV not found. Installing UV..."

    # Security: Download script first, inspect, then execute (instead of curl | sh)
    UV_INSTALL_SCRIPT=$(mktemp)
    trap "rm -f $UV_INSTALL_SCRIPT" EXIT

    echo "   Downloading UV installer..."
    if ! curl -LsSf https://astral.sh/uv/install.sh -o "$UV_INSTALL_SCRIPT"; then
        echo "❌ Failed to download UV installer"
        exit 1
    fi

    # Basic validation: check it's a shell script and not suspiciously large
    if [ ! -s "$UV_INSTALL_SCRIPT" ]; then
        echo "❌ Downloaded installer is empty"
        exit 1
    fi

    SCRIPT_SIZE=$(wc -c < "$UV_INSTALL_SCRIPT")
    if [ "$SCRIPT_SIZE" -gt 100000 ]; then
        echo "⚠️  Warning: Installer script is larger than expected ($SCRIPT_SIZE bytes)"
        echo "   Please review: $UV_INSTALL_SCRIPT"
        echo "   Or install manually: https://docs.astral.sh/uv/getting-started/installation/"
        exit 1
    fi

    echo "   Running UV installer..."
    sh "$UV_INSTALL_SCRIPT"

    # Add to PATH for this session
    export PATH="$HOME/.cargo/bin:$PATH"

    # Verify installation
    if ! command -v uv &> /dev/null; then
        echo "❌ UV installation failed"
        echo "Please install manually: https://docs.astral.sh/uv/getting-started/installation/"
        exit 1
    fi
fi

echo "✅ UV version: $(uv --version)"
echo ""

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    uv venv
    echo "✅ Virtual environment created at .venv/"
else
    echo "✅ Virtual environment already exists at .venv/"
fi

echo ""

# Activate environment
echo "Activating virtual environment..."
source .venv/bin/activate

echo "✅ Virtual environment activated"
echo ""

# Install dependencies
echo "Installing dependencies (this may take a moment)..."
uv sync

echo ""
echo "✅ Setup complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Your development environment is ready!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📝 To activate the environment in the future:"
echo "   source .venv/bin/activate"
echo "   # or use: source activate_env.sh"
echo ""
echo "📦 To install additional extras:"
echo "   uv sync --extra dev-tools    # Development utilities"
echo "   uv sync --all-extras         # Everything (recommended for contributors)"
echo ""
echo "🧪 To run tests:"
echo "   pytest"
echo ""
echo "🏃 To run the application:"
echo "   python -m smbreplay --help"
echo ""
