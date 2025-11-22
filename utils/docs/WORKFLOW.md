# SMB2 Replay Workflow Guide

This document outlines the end-to-end process for using the SMB2 Replay tool. The workflow is designed for repeatability but can feel manual—use the tips below to streamline. Always start with `smbreplay config show` to verify setup.

## Prerequisites
1. Install: `pip install -e .[dev-tools]` (includes utils).
2. Set env: `source activate_env.sh` (activates venv, sets paths).
3. System deps: `sudo apt install tshark pcapfix`.
4. Place PCAPs in `~/cases/<case_id>/` (e.g., `mkdir -p ~/cases/123; cp capture.pcap ~/cases/123/`).

## Core Workflow (6 Steps, ~5-10 min)

### 1. Configure Target Server (One-Time)
Tedious? Run once, save to config.pkl (auto-persists). Now supports interactive mode!
```
smbreplay config set server_ip 192.168.1.100
smbreplay config set domain WORKGROUP  # Or your-domain.local
smbreplay config set username testuser
smbreplay config set password yourpass
smbreplay config set tree_name testshare
smbreplay config set case_id 123  # Matches your traces folder
smbreplay config set traces_folder ~/cases
```
Or interactive: `smbreplay config --interactive` (prompts for all fields, tests connectivity).

Verify: `smbreplay config show` (password shows as *** if set).

**Tip**: For lab servers, test connectivity first: `python utils/tests/test_smb_connectivity.py`.

### 2. List Available Traces
Find PCAPs in your case folder.
```
smbreplay list traces --case 123
```
Output: Lists .pcap/.pcapng files (validates with tshark). Auto-infers case_id from current dir if possible.

**Tip**: If no case_id, set it in step 1. Use absolute paths: `smbreplay list traces --trace /path/to/capture.pcap`.

### 3. Ingest PCAP (Extract Sessions)
Process trace to Parquet (stores in `~/cases/123/.tracer/<pcap>/sessions/`).
```
smbreplay ingest --trace "capture.pcap"  # Quotes for spaces
```
- Add `-v` for progress; `--force` to re-ingest; `--reassembly` for fragmented packets.
- Takes 1-5 min depending on PCAP size. Now shows progress bar.

**Tip**: If path has spaces/subdirs: `--trace "subfolder/My Capture.pcap"`. Output confirms sessions extracted. Prompts for trace if missing.

### 4. List Sessions
View extracted SMB sessions.
```
smbreplay session --list
```
Output: Numbered list with hex IDs (e.g., 1: 0x7602000009fbdaa3). Use `--select` to pick interactively.

**Tip**: Sessions tied to ingested PCAP—re-ingest if needed. For multiple: Pipe to grep (`smbreplay session --list | grep create`).

### 5. Analyze Session (Optional, Quick Check)
Inspect ops before replay.
```
smbreplay session 3  # Uses numbered selection from list
# Or smbreplay session 0x7602000009fbdaa3 --brief  # Table view
# Or without --brief for details (file paths, status, extra fields)
```
- Filters: `--file-filter path/to/file.txt`.
- Shows: Frame #, Command (e.g., CREATE, READ), Status, Tree, Path. Rich-formatted tables.

**Tip**: --brief for large traces (truncates paths). Use to spot unsupported ops (e.g., encryption).

### 6. Replay Session
Execute ops on target server.
```
smbreplay replay 3  # Numbered selection
# Or smbreplay replay 0x7602000009fbdaa3
```
- Validates first (ops + FS); add `--validate` to check only.
- Overrides: `--server-ip 10.0.0.1 --no-ping` (skips pre-ping).
- Progress via -v; cleans up post-replay if configured. Rich progress bars.

**Tip**: If FS errors (missing dirs), run `smbreplay setup 3 --dry-run` first, then without. Cleanup: `python utils/cleanup/cleanup_test_files.py`.

## Full Example (End-to-End)
```
# Setup (one-time, interactive)
smbreplay config --interactive

# Workflow (now ~3-4 commands)
smbreplay list traces --case 123  # See: 1: capture.pcap
smbreplay ingest --trace 1 -v  # Selects by number, ingests
smbreplay session --list  # See numbered sessions
smbreplay run 1  # Chains: ingest+analyze+replay session 1 (if not ingested)
# Or manual: smbreplay session 1 --brief; smbreplay replay 1 -v
```

## Advanced/Streamlined Usage

### Reduce Tedious Steps
- **One-Command Run**: `smbreplay run --trace "capture.pcap"` (auto-ingests, lists sessions, prompts selection, replays; skips if already ingested).
- **Batch Replay**: `for id in $(smbreplay session --list --select none); do smbreplay replay $id; done` (or use --select batch).
- **Auto-Setup FS**: Before replay: `smbreplay setup <id or number> --force` (creates dirs/files).
- **Validate Only**: `smbreplay validate <id> --check-all` (aborts replay if issues; rich error tables).
- **Dev Tools**:
  - Test env: `python utils/tests/run_tests.py` (runs connectivity, replay checks).
  - Analyze mismatches: `python utils/analysis/compare_replay_to_pcap.py`.
  - Benchmark: `python utils/benchmarks/benchmark_startup.py`.
  - Capture new PCAP: `python utils/pcap/capture_setup_pcap.py`.

### Common Pain Points & Fixes
- **"No config/case_id"**: Interactive config prompts; auto-infers case_id from traces dir.
- **Path Errors**: Quotes handled; prompts for missing --trace; numbered selection avoids hex copy-paste.
- **Session Not Found**: Ensure ingest succeeded; check .tracer/ dir; auto-reingest in 'run'.
- **Replay Fails (NT_STATUS)**: Rich errors with fixes (e.g., "Run setup first"); check server perms; use --no-ping if firewall issues; validate ops support in handlers/.
- **Large PCAPs**: Use --reassembly; monitor with `psutil` (built-in); progress bars.
- **Cleanup**: Post-replay: `python utils/cleanup/force_cleanup.py` for stubborn files.

### Troubleshooting
- Logs: Check smbreplay.log; add -vvv for debug.
- Reinstall: `pip install -e . --force-reinstall`.
- tshark Issues: `tshark -v` to verify; reinstall if missing.
- For more: See README.md, INSTALLATION.md, or `smbreplay --help` (now with richer examples).

This workflow minimizes CLI calls—aim for 2-3 commands per trace with new features. Interactive modes reduce typing; numbered selection eliminates hex handling. For full TUI, consider future textual integration.