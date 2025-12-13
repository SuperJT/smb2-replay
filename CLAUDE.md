# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SMB2 Replay System - captures, stores, and replays SMB2 network traffic from PCAP files. Uses `tshark` for packet extraction, stores sessions in Parquet format, and replays operations via `smbprotocol` library against a target SMB server.

## Essential Commands

### Development Setup
```bash
# Activate environment (UV recommended)
source .venv/bin/activate

# Install with UV (fastest)
uv sync                    # Basic
uv sync --extra dev-tools  # With test utilities
uv sync --all-extras       # Everything

# Or with pip
pip install -e .           # Basic
pip install -e .[dev-full] # Everything
```

### CLI Usage
```bash
smbreplay config show                        # View config
smbreplay config set server_ip 192.168.1.100 # Set config
smbreplay list traces --case <case_id>       # List PCAP files
smbreplay ingest --trace "capture.pcap"      # Process PCAP
smbreplay session --list                     # List sessions
smbreplay session <session_id> --brief       # Analyze session
smbreplay replay <session_id>                # Execute replay
```

### Testing
```bash
pytest                                        # Run all tests
pytest --cov=smbreplay                        # With coverage
pytest -m "not slow"                          # Skip slow tests
pytest smbreplay_package/smbreplay/           # Core tests only
pytest utils/tests/                           # Utility tests
```

### Linting and Formatting
```bash
ruff check .              # Lint (replaces flake8)
ruff check . --fix        # Lint and auto-fix issues
ruff format .             # Format code (replaces black)
ruff check . --select I   # Check import sorting (replaces isort)
mypy .                    # Type check (strict mode)
```

### API Server
```bash
uvicorn api.main:app --host 0.0.0.0 --port 3004  # Run API
pytest api/tests/                                  # API tests
```

### TypeScript SDK
```bash
cd sdk && npm install && npm run build  # Build SDK
cd sdk && npm test                       # SDK tests
```

### Docker
```bash
docker build -t smbreplay-api .
docker run -d -p 3004:3004 -v ~/cases:/stingray:ro smbreplay-api
```

## Architecture

### Core Package (`smbreplay_package/smbreplay/`)
- `main.py` - CLI orchestration via `SMB2ReplaySystem` class
- `config.py` - User config storage (`~/.config/smbreplay/config.pkl`)
- `ingestion.py` - PCAP processing with tshark, outputs Parquet
- `session_manager.py` - Load/query sessions from Parquet files
- `replay.py` - Execute SMB operations via smbprotocol
- `database.py` - PostgreSQL integration for session storage
- `tshark_processor.py` - tshark interface for PCAP validation
- `handlers/` - One file per SMB2 command (create, read, write, query_directory, etc.)

### REST API (`api/`)
FastAPI-based HTTP wrapper around the core system:
- `main.py` - FastAPI app and route setup
- `routes/` - Endpoint definitions
- `services/` - Business logic layer
- `models/` - Pydantic request/response models

### TypeScript SDK (`sdk/`)
Type-safe client for Node.js/Next.js applications.

### Utilities (`utils/`)
- `analysis/` - Debug and analysis scripts
- `tests/` - Integration test scripts
- `cleanup/` - SMB server cleanup utilities
- `benchmarks/` - Performance testing

### Data Flow
```
PCAP file → tshark (ingestion.py) → Parquet sessions → replay.py → smbprotocol → target SMB server
```

## Key Patterns

### Session Management
- Sessions identified by hex ID (e.g., `0x7602000009fbdaa3`)
- Stored as `smb2_session_<id>.parquet` in `.tracer/<pcap_name>/sessions/`
- Metadata in `session_metadata.json`

### Handler Pattern
Each SMB2 command has a dedicated handler in `handlers/`:
```python
# Example: handlers/create.py handles SMB2 CREATE operations
def handle_create(op_data, connection, tree, file_handles, callbacks):
    ...
```

### Lazy Imports
Heavy dependencies (smbprotocol, pandas) imported on-demand within functions to improve startup time.

### Configuration Flow
User config → `config.py` → pickle storage → per-command overrides via CLI flags

## Code Style

- Ruff for linting AND formatting (replaces black/isort/flake8)
- 88 char line length
- Strict mypy: `disallow_untyped_defs`, `no_implicit_optional`
- 4-space indentation
- Type hints required on all function signatures
- Run `ruff check . --fix && ruff format .` before committing

## Important Gotchas

- **tshark required**: Ingestion fails without it. Install via `apt install tshark`.
- **Config before replay**: Must set `server_ip`, `username`, `password`, `tree_name` first.
- **Quote paths with spaces**: Use `--trace "My File.pcap"` for paths with spaces.
- **Session IDs are hex**: Copy exactly as shown (e.g., `0x7602000009fbdaa3`).
- **Data location**: Ingested data in `~/cases/<case_id>/.tracer/<pcap>/sessions/`.
- **No encryption default**: `require_encryption=False` for lab testing.
- **Normalize paths**: Code handles `/` vs `\` conversion for SMB compatibility.
- **Credentials in config.pkl**: File is gitignored; never commit credentials.
