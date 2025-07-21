# SMB Replay System - Utilities

This directory contains various utility scripts for testing, debugging, and managing the SMB replay system.

## Test Utilities

### `test_replay_connection.py`
**Purpose**: Test SMB connection and replay system functionality  
**Usage**: `python utils/test_replay_connection.py`  
**Tests**:
- Configuration validation
- SMB connection to localhost Samba
- User authentication
- Tree connect to testshare
- File operations (create, write, read, close)
- Replay system with simple operations

### `test_directory_creation.py`
**Purpose**: Test directory creation functionality with smbprotocol  
**Usage**: `python utils/test_directory_creation.py`  
**Tests**:
- Directory creation using smbprotocol Open.create()
- Verification of directory creation parameters
- Nested directory creation (when parent exists)

### `test_pre_trace_state.py`
**Purpose**: Test pre-trace state setup functionality  
**Usage**: `python utils/test_pre_trace_state.py`  
**Tests**:
- Pre-trace state setup logic with sample operations
- Directory and file creation in proper order
- Handling of nested paths and invalid paths
- File system structure validation
- Detailed reporting of what can/cannot be created

### `test_simple_directory.py`
**Purpose**: Test basic directory creation behavior  
**Usage**: `python utils/test_simple_directory.py`  
**Tests**:
- Simple directory creation
- Nested directory creation limitations
- File creation in nested directories

### `test_directory_listing.py`
**Purpose**: Test directory listing functionality  
**Usage**: `python utils/test_directory_listing.py`  
**Tests**:
- List root directory contents
- Verify directory creation results
- Check directory accessibility

### `test_smb_connectivity.py`
**Purpose**: Comprehensive SMB server connectivity testing  
**Usage**: `python utils/test_smb_connectivity.py`  
**Tests**:
- Basic TCP connectivity
- SMB login authentication
- Tree connect to shares
- Directory listing
- File operations (create, delete)

### `test_ping_functionality.py`
**Purpose**: Test ping functionality for replay differentiation  
**Usage**: `python utils/test_ping_functionality.py`  
**Tests**:
- Ping configuration (enable/disable)
- Ping timing (after pre-trace setup, before replay)
- Ping targets replay server automatically
- CLI ping options integration
- Network connectivity verification

### `analyze_response_mismatches.py`
**Purpose**: Analyze response mismatches and compare original vs replayed requests  
**Usage**: `python utils/analyze_response_mismatches.py <session_file>`  
**Features**:
- Runs replay and analyzes validation results
- Compares original request parameters with replayed requests
- Identifies common response mismatch patterns
- Shows detailed request analysis for mismatched operations

### `analyze_workflow_state.py`
**Purpose**: Analyze workflow state to understand file operations  
**Usage**: `python utils/analyze_workflow_state.py <session_file>`  
**Features**:
- Tracks file and directory states throughout workflow
- Identifies what files should exist vs be created
- Predicts expected responses based on file state
- Shows chronological file system changes

### `analyze_client_behavior.py`
**Purpose**: Analyze actual client behavior and operation patterns  
**Usage**: `python utils/analyze_client_behavior.py <session_file>`  
**Features**:
- Analyzes create operation parameters and responses
- Shows client intent (create vs open vs mixed)
- Interprets SMB2 create dispositions and options
- Identifies successful vs failed operations

### `setup_workflow_state.py`
**Purpose**: Set up correct file system state for replay  
**Usage**: `python utils/setup_workflow_state.py <session_file> [--dry-run]`  
**Features**:
- Creates files/directories that should exist before replay
- Analyzes what files were opened vs created in original
- Supports dry-run mode to preview changes
- Sets up exact state needed for faithful replay

## Debug Utilities

### `debug_tree_connects.py`
**Purpose**: Debug Tree Connect frames in session data  
**Usage**: `python utils/debug_tree_connects.py <session_file.parquet>`  
**Features**:
- Analyze Tree Connect operations in session files
- Show command distribution
- Examine frame structure

### `debug_delete_operation.py`
**Purpose**: Debug file deletion operations  
**Usage**: `python utils/debug_delete_operation.py`  
**Features**:
- Test different TID handling approaches
- Debug file operation issues

## Analysis Utilities

### `compare_pcap_parquet.py`
**Purpose**: Compare PCAP files with parquet session data  
**Usage**: `python utils/compare_pcap_parquet.py <pcap_file> [session_id]`  
**Features**:
- Compare frame ranges
- Analyze command distribution
- Check tree ID usage
- Validate data processing

### `check_tree_connect_frames.py`
**Purpose**: Check for specific Tree Connect frames  
**Usage**: `python utils/check_tree_connect_frames.py`  
**Features**:
- Find specific frame numbers in parquet files
- Analyze Tree Connect operations
- Compare full vs session-specific parquet files

## System Utilities

### `system_status.py`
**Purpose**: Generate system status report  
**Usage**: `python utils/system_status.py`  
**Features**:
- Configuration status
- Session data status
- Network connectivity
- SMB library status
- Supported commands

### `run_tests.py`
**Purpose**: Run all test utilities  
**Usage**: `python utils/run_tests.py`  
**Features**:
- Execute all available tests
- Generate test summary
- Overall system validation

## Quick Start

1. **Test basic connectivity**:
   ```bash
   python utils/test_simple_connectivity.py
   ```

2. **Test SMB functionality**:
   ```bash
   python utils/test_smb_connectivity.py
   ```

3. **Test replay system**:
   ```bash
   python utils/test_replay_connection.py
   ```

4. **Run all tests**:
   ```bash
   python utils/run_tests.py
   ```

## Configuration

Most utilities use the system configuration from `~/.config/smbreplay/config.pkl`. 
For local Samba testing, the configuration should be:

```python
{
    'server_ip': '127.0.0.1',
    'domain': '',
    'username': 'jtownsen', 
    'password': 'P@ssw0rd',
    'tree_name': 'testshare',
    'max_wait': 5.0
}
```

## Troubleshooting

- **Connection timeouts**: Check if Samba service is running (`sudo systemctl status smbd`)
- **Authentication failures**: Verify Samba user exists (`sudo pdbedit -L`)
- **Access denied**: Check share permissions in `/etc/samba/smb.conf`
- **Configuration issues**: Use `smbreplay config show` to verify settings 