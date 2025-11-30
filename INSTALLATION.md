# SMB2 Replay Installation Guide

This guide explains the different installation options available for the SMB2 Replay System.

## Installation Options

### 1. Basic Installation (Recommended for New Users)

For users who want to use the core SMB2 replay functionality:

```bash
# Clone the repository
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Create virtual environment
python3 -m venv venv --copies
source venv/bin/activate

# Install basic package
pip install -e .

# Test installation
python smbreplay_package/smbreplay/test_environment.py
```

**What's included:**
- Core SMB2 replay functionality
- Command-line interface (`smbreplay` command)
- Basic configuration management
- Session analysis and replay capabilities

**What's NOT included:**
- Development utilities
- Advanced analysis tools
- Test suites
- Debugging tools

### 2. Development Tools Installation (For Developers and Advanced Users)

For users who need additional development, testing, and analysis capabilities:

```bash
# Clone the repository
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Create virtual environment
python3 -m venv venv --copies
source venv/bin/activate

# Install with development tools
pip install -e .[dev-tools]

# Test installation
python smbreplay_package/smbreplay/test_environment.py
```

**What's included:**
- Everything from basic installation
- Development utilities (`utils/` directory)
- Test suites and connectivity testing
- Advanced analysis tools
- Performance benchmarking tools
- PCAP capture utilities
- File cleanup tools

### 3. Full Development Installation (For Contributors)

For developers contributing to the project:

```bash
# Clone the repository
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Create virtual environment
python3 -m venv venv --copies
source venv/bin/activate

# Install with all development dependencies
pip install -e .[dev-full]

# Test installation
python smbreplay_package/smbreplay/test_environment.py
```

**What's included:**
- Everything from development tools installation
- Code quality tools (black, flake8, mypy, isort)
- Testing framework (pytest, pytest-cov)
- Development utilities

## System Requirements

### Prerequisites

- Python 3.8 or higher
- Linux/WSL2 environment
- Virtual environment support (`venv`)

### System Tools

Install these system dependencies:

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install tshark pcapfix

# Verify installations
tshark -v
pcapfix --help
```

## Verification

After installation, verify your setup:

```bash
# Test basic functionality
smbreplay config show

# Test environment (if installed with dev-tools)
python smbreplay_package/smbreplay/test_environment.py

# Test SMB connectivity (if installed with dev-tools)
python utils/tests/test_smb_connectivity.py
```

## Available Commands

### Basic Commands (All Installations)

```bash
smbreplay config show          # Show configuration
smbreplay list traces          # List available PCAP files
smbreplay ingest --trace file  # Process PCAP file
smbreplay session --list       # List SMB sessions
smbreplay session <id>         # Show session details
smbreplay replay <id>          # Replay session
```

### Development Commands (Dev-Tools Installation)

```bash
# Testing and connectivity
python utils/tests/test_smb_connectivity.py
python utils/tests/run_tests.py

# Cleanup utilities
python utils/cleanup/cleanup_test_files.py
python utils/cleanup/force_cleanup.py

# Analysis tools
python utils/analysis/setup_workflow_state.py
python utils/analysis/analyze_client_behavior.py

# Performance testing
python utils/benchmarks/benchmark_startup.py

# PCAP capture
python utils/pcap/capture_setup_pcap.py
```

## Troubleshooting

### Common Issues

1. **"tshark not found"**
   ```bash
   sudo apt install tshark
   ```

2. **"pcapfix not found"**
   ```bash
   sudo apt install pcapfix
   ```

3. **Import errors with development tools**
   ```bash
   # Reinstall with dev-tools
   pip install -e .[dev-tools]
   ```

4. **Permission errors**
   ```bash
   # Make sure you're in the virtual environment
   source venv/bin/activate
   ```

### Getting Help

- Check the main [README.md](README.md) for usage examples
- Review the [RELEASE_NOTES_1.0.0.md](RELEASE_NOTES_1.0.0.md) for known issues
- Use `smbreplay --help` for command-line help 