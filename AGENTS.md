# SMB2 Replay System - Agent Guide

## Project Overview

This is a Python-based tool for capturing, analyzing, and replaying SMB2 network traffic. It processes PCAP files using tshark to extract SMB2 sessions, stores them in Parquet format, and replays operations using the smbprotocol library against a target SMB server. The project targets Python 3.8+ and is structured as a CLI package with additional utility scripts.

Key components:
- Core package: `smbreplay_package/smbreplay/` - Handles ingestion, session management, replay logic, and SMB handlers.
- Utilities: `utils/` - Analysis scripts, benchmarks, cleanup tools, tests, and PCAP capture utilities.
- Configuration: User-specific settings stored in `~/.config/smbreplay/config.pkl` (Linux/macOS) or `%LOCALAPPDATA%\smbreplay\config.pkl` (Windows).

The project uses Agentic Tools for task management and follows a modular design with protocol-specific handlers.

## Installation and Setup

### Prerequisites
- Python 3.8+
- tshark (Wireshark CLI) and pcapfix (for PCAP processing)
- Linux/WSL2 environment recommended

Install system dependencies (Ubuntu/Debian):
```
sudo apt update && sudo apt install tshark pcapfix
```

### Virtual Environment and Package Installation
Create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or venv\Scripts\activate  # Windows
```

Install the package:
- Basic (core functionality): `pip install -e .`
- With dev tools (analysis, tests): `pip install -e .[dev-tools]`
- Full dev (linting, testing, tools): `pip install -e .[dev-full]`

Verify installation:
```
smbreplay config show
python smbreplay_package/smbreplay/test_environment.py
```

### Development Workflow
- Use `activate_env.sh` to activate environment and set paths.
- Configuration is managed via CLI: `smbreplay config set <key> <value>`.
- Traces stored in `~/cases/<case_id>/` by default (set via `TRACES_FOLDER` env or config).

## Essential Commands

### Core CLI Commands (smbreplay)
All commands require configuration setup first (`smbreplay config show` to verify).

- View configuration: `smbreplay config show`
- Set config: `smbreplay config set server_ip 192.168.1.100` (keys: server_ip, domain, username, password, tree_name, case_id, traces_folder)
- List traces: `smbreplay list traces --case 2010101010`
- Ingest PCAP: `smbreplay ingest --trace "capture.pcap"` (use quotes for paths with spaces; supports --force, --reassembly)
- List sessions: `smbreplay session --list`
- Analyze session: `smbreplay session <session_id> --brief` (or without --brief for details)
- Replay session: `smbreplay replay <session_id>` (supports --validate, --no-ping, --server-ip etc. overrides)
- Validate readiness: `smbreplay validate <session_id>` (checks ops and FS; supports --check-fs, --check-ops)
- Setup FS: `smbreplay setup <session_id>` (creates dirs/files; supports --dry-run, --force)

Add `-v` (multiple for more verbosity) to any command.

### Utility Scripts (with dev-tools)
Run from `utils/`:
- Connectivity tests: `python utils/tests/test_smb_connectivity.py`
- Full test suite: `python utils/tests/run_tests.py`
- Cleanup: `python utils/cleanup/cleanup_test_files.py`
- Analysis: `python utils/analysis/analyze_client_behavior.py` (various analysis tools)
- Benchmarks: `python utils/benchmarks/benchmark_startup.py`
- PCAP capture: `python utils/pcap/capture_setup_pcap.py`

## Testing

Uses pytest for unit/integration tests.

- Run all tests: `python -m pytest` (or `pytest`)
- With coverage: `python -m pytest --cov=smbreplay`
- Specific paths: `pytest smbreplay_package/smbreplay/` (core), `pytest utils/tests/` (utils)
- Markers: `--strict-markers`; deselect slow tests: `pytest -m "not slow"`

Test paths: `tests/` and `utils/tests/`. Includes unit, integration, slow markers.

Config: `[tool.pytest.ini_options]` in pyproject.toml specifies paths, files, addopts.

After changes: Run `pytest` immediately; fix failures before proceeding.

## Linting and Formatting

Enforced via dev dependencies (black, isort, flake8, mypy).

- Format code: `black .` (line-length=88)
- Sort imports: `isort .` (profile="black", known_first_party=["smbreplay"])
- Lint: `flake8 .` (max-line-length=88, ignores E203,E501,W503,W504; excludes build dirs, venv, etc.)
- Type check: `mypy .` (strict mode: disallow_untyped_defs, etc.; ignores third-party like smbprotocol)

Pre-commit hooks not configured; run manually after edits.

Config files: `.flake8`, `mypy.ini`, `[tool.black]`, `[tool.isort]`, `[tool.flake8]` in pyproject.toml.

## Code Structure

### Core Package: smbreplay_package/smbreplay/
- `__main__.py`: CLI entry point (runs main()).
- `main.py`: Orchestrates system (SMB2ReplaySystem class); handles CLI parsing, ingestion, replay, validation, setup.
- `config.py`: Manages user config (get_config, set values); stores in pickle.
- `constants.py`: Defines SMB constants, tshark checks.
- `ingestion.py`: Processes PCAP with tshark; extracts sessions to Parquet/JSON.
- `replay.py`: Replays operations using smbprotocol; validates ops, handles callbacks.
- `session_manager.py`: Loads/summarizes sessions from Parquet; updates operations.
- `tshark_processor.py`: Interfaces with tshark for PCAP validation, packet count.
- `utils.py`: General utilities (logging, paths, etc.).
- `handlers/`: Protocol-specific (one file per SMB command, e.g., `negotiate.py`, `create.py`, `read.py`); implements replay logic for each op.

### Utilities: utils/
- `analysis/`: Scripts for behavior analysis, response mismatches, workflow state (e.g., `analyze_client_behavior.py`).
- `benchmarks/`: Performance tests (e.g., `benchmark_startup.py`).
- `cleanup/`: Removes test files from SMB server (e.g., `cleanup_test_files.py`).
- `docs/`: Documentation (README.md, SMB_DIRECTORY_CREATION.md).
- `pcap/`: PCAP capture setup (e.g., `capture_setup_pcap.py`).
- `tests/`: Test scripts (e.g., `test_smb_connectivity.py`, `run_tests.py` for custom runner).

### Config and Build
- `pyproject.toml`: Project metadata, dependencies (core: smbprotocol, pandas, pyarrow; dev: black, pytest; dev-tools: paramiko, scapy), tool configs (black, isort, flake8, mypy, pytest, coverage).
- `setup.py`: Builds package; reads requirements, includes utils with dev-tools.
- `requirements.txt`: Core deps (pandas>=2.0, smbprotocol>=1.8, etc.).
- `.gitignore`: Ignores venv, build artifacts, logs, PCAPs, cases/, config.pkl, coverage files.

Data flow: PCAP → tshark (ingestion) → Parquet sessions → Analysis/Replay via handlers → smbprotocol to target server.

## Conventions and Patterns

### Code Style
- PEP 8 compliant with Black formatting (line-length=88, target py38+).
- Imports: isort organized (STDLIB, THIRDPARTY, FIRSTPARTY); known_first_party=["smbreplay"].
- Logging: Uses logging.getLogger(__name__); levels: info for progress, debug for details.
- Typing: Strict mypy (disallow_untyped_defs, no_implicit_optional); uses typing.Dict, List, Optional.
- Error handling: Try/except for SMBExceptions; validate before replay; graceful BrokenPipeError in CLI.
- Paths: Normalize \ vs /; use os.path.abspath, pathlib.
- CLI: Argparse with subparsers; safe_print for output (handles pipes); verbosity via -v count.

### Architecture Patterns
- Lazy imports: Heavy modules (e.g., smbprotocol) imported on-demand in functions.
- Callbacks: Status callbacks for progress (ingestion, replay).
- Config: Centralized in config.py; replay-specific in replay_config dict.
- Sessions: Identified by hex ID (e.g., 0x7602000009fbdaa3); stored as smb2_session_<id>.parquet.
- Handlers: Each SMB command has a dedicated handler class/method (e.g., handle_negotiate); skips negotiate (uses existing connection).
- Validation: Pre-replay checks for ops support, FS structure (missing dirs, created/existing files).
- FS Setup: Creates dirs/files in depth order; cleanup with FILE_DELETE_ON_CLOSE.

### Testing Patterns
- Pytest: test_*.py files; classes Test*; functions test_*.
- Markers: unit, integration, slow.
- Coverage: Omit tests, __pycache__, venv; exclude pragmas, __repr__, debug ifs.
- Utils tests: Custom runner in run_tests.py executes specific scripts (connectivity, replay).

### Git and Versioning
- Branch: master
- Commits: Semantic (feat:, chore:, style:); recent: test coverage, VS Code config.
- No CI configs observed; manual testing/linting.

## Gotchas and Notes

- **tshark Required**: Ingestion fails without tshark; check with `tshark -v`. Install via apt.
- **Config First**: Replay/validate/setup require server config (server_ip, etc.); default password="PASSWORD" – update it.
- **PCAP Paths**: Use quotes for spaces/special chars; relative paths need case_id configured.
- **Session IDs**: Hex format (e.g., 0x...); construct filenames as smb2_session_<id>.parquet.
- **Data Storage**: Ingested data in `~/cases/<case_id>/.tracer/<pcap_name>/sessions/`; .gitignore excludes cases/, PCAPs, Parquet.
- **SMB Server**: Replay targets lab server; no encryption by default (require_encryption=False); handles negotiate via existing connection.
- **Dry Runs**: Use --dry-run in setup/validate to preview without changes.
- **Large Sessions**: Use --brief for analysis; truncate long paths/status in output.
- **Windows Paths**: Code normalizes / to \ for SMB; supports both in inputs.
- **Dev Tools**: Utils/ included only with [dev-tools]; paramiko/scapy for advanced networking.
- **No Auto-Cleanup**: Manually run cleanup scripts post-replay; force_cleanup.py for stubborn files.
- **Memory/Perf**: Pandas/pyarrow for Parquet; psutil for monitoring; benchmarks in utils/.
- **Security**: Config.pkl stores credentials (gitignored); never commit sensitive data.
- **Editing**: Always view files before edit (exact whitespace: 4 spaces indent, Black style). Run pytest after changes.

For contributions: Fork, branch, test, lint, update docs, PR with details. Focus on protocol accuracy, error handling, performance.