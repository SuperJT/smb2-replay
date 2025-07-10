#!/bin/bash
# Convenience script to activate the virtual environment
# Usage: source activate_env.sh

echo "Activating SMB2 Replay virtual environment..."
source venv/bin/activate
echo "Virtual environment activated!"
echo "Python version: $(python --version)"
echo "Current directory: $(pwd)"
echo ""
echo "To run Jupyter Lab: jupyter lab"
echo "To run Jupyter Notebook: jupyter notebook"
echo "To deactivate: deactivate" 