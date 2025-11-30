# SMBReplay Code Formatting Inventory

## Overview
This document provides a complete inventory of all Python files in the SMBReplay project that need formatting.

**Total Files to Format**: 32 files in smbreplay package + 2 additional files
**Total Lines**: 8,398 lines in smbreplay package
**Total Size**: ~300KB in smbreplay package

## File Categories

### 1. Core Module Files (Priority: High)
These are the foundational files that other modules depend on.

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `__init__.py` | 218 | 7.3K | Package initialization |
| `config.py` | 426 | 16K | Configuration management |
| `constants.py` | 395 | 14K | Constants and definitions |
| `utils.py` | 476 | 12K | Utility functions |

### 2. Large Core Files (Priority: High - Handle Carefully)
These are the largest and most complex files that contain main functionality.

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `main.py` | 1,796 | 76K | Main CLI entry point |
| `replay.py` | 1,098 | 50K | Replay functionality |
| `session_manager.py` | 795 | 34K | Session management |
| `ingestion.py` | 640 | 25K | PCAP ingestion |
| `tshark_processor.py` | 487 | 20K | TShark integration |

### 3. Handler Module Files (Priority: Medium)
These are smaller, focused files that handle specific SMB2 operations.

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `handlers/__init__.py` | 59 | 1.7K | Handler initialization |
| `handlers/query_directory.py` | 199 | 8.7K | Directory query handling |
| `handlers/query_info.py` | 157 | 7.8K | Info query handling |
| `handlers/ioctl.py` | 155 | 6.5K | IOCTL handling |
| `handlers/create.py` | 106 | 4.8K | File creation handling |
| `handlers/change_notify.py` | 94 | 4.1K | Change notification |
| `handlers/lock.py` | 89 | 3.9K | File locking |
| `handlers/lease_break.py` | 88 | 3.6K | Lease break handling |
| `handlers/oplock_break.py` | 65 | 2.6K | Oplock break handling |
| `handlers/echo.py` | 57 | 2.3K | Echo handling |
| `handlers/cancel.py` | 52 | 2.1K | Cancel operation |
| `handlers/set_info.py` | 49 | 2.0K | Set info handling |
| `handlers/flush.py` | 43 | 1.8K | Flush handling |
| `handlers/read.py` | 24 | 986B | Read handling |
| `handlers/write.py` | 24 | 1.1K | Write handling |
| `handlers/close.py` | 22 | 790B | Close handling |
| `handlers/response.py` | 18 | 831B | Response handling |
| `handlers/tree_connect.py` | 9 | 357B | Tree connect |
| `handlers/tree_disconnect.py` | 6 | 207B | Tree disconnect |
| `handlers/session_setup.py` | 6 | 189B | Session setup |
| `handlers/logoff.py` | 6 | 192B | Logoff handling |
| `handlers/negotiate.py` | 6 | 184B | Negotiate handling |

### 4. Test and Utility Files (Priority: Medium)
These are test files and utility modules.

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `performance_monitor.py` | 382 | 15K | Performance monitoring |
| `test_conversion.py` | 199 | 5.7K | Conversion testing |
| `test_environment.py` | 132 | 4.2K | Environment testing |
| `__main__.py` | 20 | 460B | Module entry point |

### 5. Additional Files (Priority: Low)
These are outside the main package but may need formatting.

| File | Lines | Size | Description |
|------|-------|------|-------------|
| `setup.py` | ~100 | ~3K | Package setup |
| `debug_create_action.py` | ~65 | ~2.3K | Debug utility |

### 6. Utils Directory Files (Priority: Low)
These are utility scripts in the utils/ directory.

**Analysis Utils** (8 files):
- `utils/analysis/analyze_client_behavior.py`
- `utils/analysis/analyze_response_mismatches.py`
- `utils/analysis/analyze_workflow_state.py`
- `utils/analysis/check_tree_connect_frames.py`
- `utils/analysis/compare_pcap_parquet.py`
- `utils/analysis/compare_replay_to_pcap.py`
- `utils/analysis/debug_tree_connects.py`
- `utils/analysis/setup_workflow_state.py`

**Benchmark Utils** (4 files):
- `utils/benchmarks/benchmark_startup.py`
- `utils/benchmarks/detailed_config_benchmark.py`
- `utils/benchmarks/import_analysis.py`
- `utils/benchmarks/minimal_config_test.py`

**Cleanup Utils** (2 files):
- `utils/cleanup/cleanup_test_files.py`
- `utils/cleanup/force_cleanup.py`

**Test Utils** (18 files):
- Various test files in `utils/tests/`

## Formatting Strategy

### Phase 1: Core Dependencies
1. Format core module files first (__init__.py, config.py, constants.py, utils.py)
2. Test each file after formatting to ensure imports still work

### Phase 2: Handler Files
1. Format handler files in order of complexity (smallest to largest)
2. Test each handler after formatting

### Phase 3: Large Core Files
1. Format large files one at a time with extensive testing
2. Start with tshark_processor.py, then ingestion.py, session_manager.py, replay.py, main.py

### Phase 4: Test and Utility Files
1. Format remaining files in the main package
2. Test functionality

### Phase 5: Additional Files
1. Format setup.py and debug_create_action.py
2. Consider formatting utils/ files if needed

## Notes

- **Auto-generated files**: None identified - all files appear to be manually written
- **Critical files**: main.py, replay.py, session_manager.py are the most critical and should be handled with extra care
- **Dependencies**: Core files should be formatted first as other files depend on them
- **Testing**: Each file should be tested after formatting to ensure functionality is preserved
- **Backup strategy**: Create backups before formatting each file

## Risk Assessment

**High Risk Files**:
- `main.py` (1,796 lines) - Main CLI entry point
- `replay.py` (1,098 lines) - Core replay functionality
- `session_manager.py` (795 lines) - Session management

**Medium Risk Files**:
- `ingestion.py` (640 lines) - PCAP processing
- `tshark_processor.py` (487 lines) - External tool integration
- `config.py` (426 lines) - Configuration management

**Low Risk Files**:
- Handler files (mostly small and focused)
- Test files (can be regenerated if needed)
- Utility files (less critical to core functionality) 