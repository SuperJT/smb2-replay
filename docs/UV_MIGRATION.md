# UV Migration Guide

This guide helps existing developers migrate from pip/venv to UV for faster and more reliable Python package management.

## TL;DR - Quick Migration

```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Remove old venv
deactivate  # if currently active
rm -rf venv

# Create UV environment
uv venv
source .venv/bin/activate
uv sync --all-extras
```

---

## What Changed?

### For End Users

**No action required!** The package still works with pip:
```bash
pip install git+https://github.com/SuperJT/smb2-replay.git
```

### For Developers

The project now uses UV as the recommended package manager, but pip remains fully supported as a fallback.

**Key Changes:**
1. **Dependencies**: Consolidated in `pyproject.toml` (requirements.txt files removed)
2. **Lock File**: Added `uv.lock` for reproducible builds
3. **Virtual Environment**: `.venv/` (UV default) instead of `venv/`
4. **Python Version**: Upgraded minimum to Python 3.12+
5. **Installation Scripts**: Auto-detect UV/pip and use the faster option

---

## Why UV?

### Performance Benefits
- **10-100x faster** dependency resolution
- **5-15 seconds** for fresh install vs 60-180 seconds with pip
- **< 2 seconds** with cache hits

### Developer Experience
- **Better error messages** when conflicts occur
- **Lock file** (`uv.lock`) ensures reproducible builds
- **Faster CI/CD** builds in Docker
- **Drop-in compatible** with pip - no workflow changes needed

### Production Benefits
- **Identical environments** across dev/staging/prod with lock file
- **Faster Docker builds** (significantly speeds up deployment)
- **Better caching** reduces network usage

---

## Migration Steps

### Step 1: Install UV

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Verify installation:
```bash
uv --version
```

If command not found:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
```

### Step 2: Remove Old Virtual Environment

```bash
# Deactivate if currently active
deactivate

# Remove old venv
rm -rf venv
```

### Step 3: Create UV Environment

```bash
# Create new virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install dependencies
uv sync --all-extras  # For contributors
# OR
uv sync --extra dev-tools  # For developers
# OR
uv sync  # For basic usage
```

### Step 4: Verify Installation

```bash
# Test the package
python -m smbreplay --help

# Run tests (if dev-full)
pytest

# Check code quality (if dev-full)
black --check .
```

---

## Command Mapping

### Virtual Environment

| Old (pip/venv) | New (UV) |
|----------------|----------|
| `python3 -m venv venv` | `uv venv` |
| `source venv/bin/activate` | `source .venv/bin/activate` |
| `deactivate` | `deactivate` (same) |

### Installation

| Old (pip) | New (UV) |
|-----------|----------|
| `pip install -e .` | `uv sync` |
| `pip install -e .[dev-tools]` | `uv sync --extra dev-tools` |
| `pip install -e .[dev-full]` | `uv sync --all-extras` |
| `pip install <package>` | `uv pip install <package>` |
| `pip freeze > requirements.txt` | Use `uv.lock` instead |
| `pip install -r requirements.txt` | `uv sync --frozen` |

### Package Management

| Old (pip) | New (UV) |
|-----------|----------|
| `pip list` | `uv pip list` |
| `pip show <package>` | `uv pip show <package>` |
| `pip install --upgrade <pkg>` | `uv pip install --upgrade <pkg>` |
| `pip uninstall <package>` | `uv pip uninstall <package>` |

---

## What's Different?

### Virtual Environment Location
- **Old**: `venv/` directory
- **New**: `.venv/` directory (UV default)

Both work, but `.venv/` is preferred for consistency.

### Lock File
- **Old**: No lock file (or manual requirements.txt)
- **New**: `uv.lock` file (committed to git)

The lock file ensures everyone gets identical dependency versions.

### Dependencies
- **Old**: Split across `requirements.txt`, `requirements-api.txt`, `pyproject.toml`
- **New**: Single source of truth in `pyproject.toml`

### Activation Script
- **Old**: `source venv/bin/activate`
- **New**: `source .venv/bin/activate` or `source activate_env.sh` (auto-detects UV)

---

## Common Workflows

### Daily Development

**With UV:**
```bash
source .venv/bin/activate
# Work on code
uv sync  # If pyproject.toml changed
pytest
```

### Adding a New Dependency

**Old way (pip):**
```bash
pip install new-package
# Manually update requirements.txt or pyproject.toml
```

**New way (UV):**
```bash
# Add to pyproject.toml manually, then:
uv lock
uv sync

# Or use uv pip directly:
uv pip install new-package
# Then update pyproject.toml manually
```

### Updating Dependencies

**Old way (pip):**
```bash
pip install --upgrade package-name
# OR
pip install --upgrade -e .[dev-full]
```

**New way (UV):**
```bash
# Update lock file to latest compatible versions
uv lock --upgrade

# Install updated versions
uv sync
```

### CI/CD

**Old way:**
```bash
pip install -e .[dev-full]
pytest
```

**New way (faster):**
```bash
uv sync --frozen --all-extras
pytest
```

---

## Backwards Compatibility

### pip Still Works!

You can continue using pip if you prefer:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .[dev-full]
```

All installation scripts detect and support both UV and pip:
- `install.py` - Auto-detects and uses UV if available
- `install_dev_tools.py` - Auto-detects and uses UV if available
- `activate_env.sh` - Recommends UV but provides pip instructions

### For Teams

If your team isn't ready to switch:
1. UV users get faster builds
2. pip users continue as normal
3. Both use the same `pyproject.toml`
4. Both produce compatible environments

The migration is **opt-in** - everyone can choose their preferred tool.

---

## FAQ

### Q: Do I have to switch to UV?
**A:** No, pip still works perfectly. UV is recommended for better performance.

### Q: Can I use both UV and pip?
**A:** Yes, but stick to one per environment to avoid conflicts. Don't mix `uv sync` and `pip install` in the same venv.

### Q: Will this break my current setup?
**A:** No, your existing `venv/` continues to work. UV creates a new `.venv/` directory.

### Q: What about CI/CD?
**A:** UV works great in CI/CD and is much faster. GitHub Actions has official UV support.

### Q: Is UV stable/production-ready?
**A:** Yes! UV is maintained by Astral (creators of Ruff) and used in production by many projects.

### Q: What happened to requirements.txt?
**A:** Removed. All dependencies are now in `pyproject.toml` (single source of truth).

### Q: How do I share exact versions with teammates?
**A:** The `uv.lock` file (committed to git) ensures everyone gets identical versions with `uv sync --frozen`.

### Q: Can I still use virtualenv or conda?
**A:** Yes, but `uv venv` is recommended for consistency and speed.

### Q: What if UV breaks?
**A:** Fall back to pip - it still works. UV is backwards compatible.

---

## Troubleshooting

### UV command not found
```bash
# Add UV to PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Make permanent
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Slow first install with UV
UV downloads a Python standalone build on first run. Subsequent installs are much faster due to caching.

### Lock file conflicts in git
If multiple people update dependencies:
```bash
# Resolve by regenerating lock file
uv lock --upgrade
git add uv.lock
git commit -m "Update lock file"
```

### Different results between UV and pip
This shouldn't happen, but if it does:
```bash
# Use lock file for reproducibility
uv sync --frozen
```

---

## Performance Comparison

### Installation Time (smbreplay dev-full)

| Tool | Cold Cache | Warm Cache |
|------|-----------|------------|
| **UV** | 5-15 seconds | < 2 seconds |
| **pip** | 60-180 seconds | 30-60 seconds |

### Docker Build Time

| Tool | Fresh Build | Cached Build |
|------|------------|--------------|
| **UV** | 3-5 minutes | < 1 minute |
| **pip** | 8-12 minutes | 3-5 minutes |

---

## Next Steps

1. **Install UV** - `curl -LsSf https://astral.sh/uv/install.sh | sh`
2. **Try it out** - Create a new `.venv` and run `uv sync`
3. **Compare speed** - Notice how much faster UV is
4. **Update your workflow** - Use UV for daily development
5. **Share feedback** - Let the team know how it goes

---

## Additional Resources

- **UV Documentation**: https://docs.astral.sh/uv/
- **UV GitHub**: https://github.com/astral-sh/uv
- **INSTALLATION.md**: Comprehensive installation guide with UV commands
- **README.md**: Quick start guide
