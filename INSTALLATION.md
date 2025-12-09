# SMB2 Replay Installation Guide

This guide explains the different installation options available for the SMB2 Replay System.

## Package Manager: UV vs pip

SMB2 Replay supports both UV and pip for package management:

### UV (Recommended)
- **10-100x faster** dependency resolution and installation
- **Better caching** and reproducibility with lock files
- **Drop-in compatible** with pip and PyPI ecosystem
- Install: `curl -LsSf https://astral.sh/uv/install.sh | sh`

### pip (Traditional)
- Standard Python package installer
- Universally available
- Slower but reliable
- Use if UV is not available or preferred

**All commands below show both UV and pip variants.** UV is recommended for better performance.

---

## Installation Options

### 1. Quick Setup (Easiest - UV Required)

For the fastest setup experience:

```bash
# Install UV if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and run automated setup
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay
./scripts/setup-uv.sh

# Test installation
python -m smbreplay --help
```

This script automatically:
- Installs UV (if needed)
- Creates a virtual environment
- Installs all dependencies
- Activates the environment

---

### 2. Basic Installation (Recommended for New Users)

For users who want to use the core SMB2 replay functionality:

**With UV (Recommended)**
```bash
# Clone the repository
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Create virtual environment and install
uv venv
source .venv/bin/activate
uv sync

# Test installation
python -m smbreplay --help
```

**With pip (Traditional)**
```bash
# Clone the repository
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Create virtual environment and install
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Test installation
python -m smbreplay --help
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
- API dependencies

---

### 3. Development Tools Installation (For Developers and Advanced Users)

For users who need additional development, testing, and analysis capabilities:

**With UV (Recommended)**
```bash
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

uv venv
source .venv/bin/activate
uv sync --extra dev-tools

# Test installation
python utils/tests/test_smb_connectivity.py
```

**With pip (Traditional)**
```bash
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

python3 -m venv venv
source venv/bin/activate
pip install -e .[dev-tools]

# Test installation
python utils/tests/test_smb_connectivity.py
```

**What's included:**
- Everything from basic installation
- Development utilities (`utils/` directory)
- Test suites and connectivity testing
- Advanced analysis tools
- Performance benchmarking tools
- PCAP capture utilities
- File cleanup tools

---

### 4. Full Development Installation (For Contributors)

For developers contributing to the project:

**With UV (Recommended)**
```bash
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

uv venv
source .venv/bin/activate
uv sync --all-extras

# Run code quality checks
black --check .
pytest
```

**With pip (Traditional)**
```bash
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

python3 -m venv venv
source venv/bin/activate
pip install -e .[dev-full]

# Run code quality checks
black --check .
pytest
```

**What's included:**
- Everything from development tools installation
- Code quality tools (black, flake8, mypy, isort)
- Testing framework (pytest, pytest-cov)
- API dependencies (FastAPI, uvicorn, pydantic)
- All development utilities

---

### 5. Install from GitHub (No Clone Required)

For quick installation without cloning:

**With UV**
```bash
# Latest version
uv pip install git+https://github.com/SuperJT/smb2-replay.git

# Specific version
uv pip install git+https://github.com/SuperJT/smb2-replay.git@v1.1.0

# With extras
uv pip install "git+https://github.com/SuperJT/smb2-replay.git#egg=smbreplay[dev-full]"
```

**With pip**
```bash
# Latest version
pip install git+https://github.com/SuperJT/smb2-replay.git

# Specific version
pip install git+https://github.com/SuperJT/smb2-replay.git@v1.1.0

# With extras
pip install "git+https://github.com/SuperJT/smb2-replay.git#egg=smbreplay[dev-full]"
```

---

## System Requirements

### Prerequisites

- **Python 3.12 or higher** (tested with Python 3.12.3)
- **Linux/WSL2 environment**
- **UV** (recommended) or **pip** for package management
- **tshark**: Wireshark command-line tool for packet capture analysis
- **capinfos**: Wireshark utility for PCAP file information
- **pcapfix**: PCAP file repair utility

### Installing System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update && sudo apt install tshark pcapfix

# Verify installations
tshark -v
pcapfix --help
```

**Installing UV:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add to PATH for current session
export PATH="$HOME/.cargo/bin:$PATH"

# Verify installation
uv --version
```

---

## Command Reference

### Installation Commands

| Installation Type | UV Command | pip Command |
|-------------------|------------|-------------|
| Basic | `uv sync` | `pip install -e .` |
| Dev-tools | `uv sync --extra dev-tools` | `pip install -e .[dev-tools]` |
| Dev-full | `uv sync --all-extras` | `pip install -e .[dev-full]` |
| From GitHub | `uv pip install git+https://...` | `pip install git+https://...` |

### Virtual Environment Commands

| Task | UV Command | pip Command |
|------|------------|-------------|
| Create venv | `uv venv` | `python3 -m venv venv` |
| Activate (Linux) | `source .venv/bin/activate` | `source venv/bin/activate` |
| Install dependencies | `uv sync` | `pip install -e .` |
| Update dependencies | `uv lock --upgrade && uv sync` | `pip install --upgrade -e .` |

---

## Interactive Installer

For a guided installation experience, use the interactive installer:

```bash
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Activate a virtual environment first (UV or pip)
uv venv && source .venv/bin/activate
# OR
python3 -m venv venv && source venv/bin/activate

# Run interactive installer
python install.py
```

The installer will:
- Auto-detect UV or pip
- Prompt you to choose installation type (Basic, Dev-tools, Dev-full)
- Install the selected configuration
- Test the installation
- Show next steps

---

## Lock File for Reproducibility

If you're using UV, the project includes a `uv.lock` file for reproducible installations:

```bash
# Install exact versions from lock file
uv sync --frozen

# Update lock file with latest compatible versions
uv lock --upgrade
uv sync
```

The lock file ensures identical dependencies across development and production environments.

---

## Upgrading Dependencies

### With UV (Recommended)
```bash
# Update lock file to latest compatible versions
uv lock --upgrade

# Install updated dependencies
uv sync
```

### With pip
```bash
# Upgrade all dependencies
pip install --upgrade -e .[dev-full]
```

---

## Troubleshooting

### UV Not Found

If `uv` command is not found after installation:

```bash
# Add to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Add to shell profile for persistence
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Or use full path
~/.cargo/bin/uv --version
```

### UV vs pip Performance Comparison

Typical installation times (cold cache):
- **UV**: 5-15 seconds for fresh install
- **pip**: 60-180 seconds for fresh install

Cache hits are even faster with UV (< 2 seconds).

### Python Version Mismatch

If you get a Python version error:

```bash
# Check your Python version
python --version

# Ensure Python 3.12+
# Install Python 3.12 if needed:
sudo apt update
sudo apt install python3.12 python3.12-venv
```

---

## Next Steps

After installation:

1. **Configure target server**:
   ```bash
   smbreplay config set server_ip <your-server-ip>
   smbreplay config set username <your-username>
   smbreplay config show
   ```

2. **Test connectivity** (dev-tools required):
   ```bash
   python utils/tests/test_smb_connectivity.py
   ```

3. **Run tests** (dev-full required):
   ```bash
   pytest
   black --check .
   mypy smbreplay_package/
   ```

---

## Additional Resources

- **README.md** - Project overview and quick start
- **docs/UV_MIGRATION.md** - Migrating from pip to UV
- **GitHub Issues** - Report bugs or request features
- **API Documentation** - `/api/docs` when running the API server
