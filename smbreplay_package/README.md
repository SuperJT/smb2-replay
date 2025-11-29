# SMB2 Replay Project

This project provides a system to capture, store, and replay SMB2 (Server Message Block version 2) network traffic for diagnostic, testing, and protocol analysis purposes in a controlled lab environment.

**Repository**: https://github.com/SuperJT/smb2-replay

## Project Overview

### Objective
Develop a system to capture, store, and replay SMB2 network traffic for diagnostic, testing, and protocol interaction analysis, critical for file sharing in Windows-based systems.

### Approach
- **Capture**: Extract SMB2 packets from PCAP files using local `tshark`
- **Storage**: Store data in Parquet files by session (`smb2.sesid`) with JSON metadata
- **Replay**: Replicate file operations using `smbprotocol` library on a lab server
- **Analysis**: Python package with CLI and programmatic interfaces for automation
- **Development**: Modular design with separate components for different functionalities

### Server Configuration
- **IP**: 192.168.1.100 (configurable)
- **Domain**: example.local (configurable)
- **Username**: testuser (configurable)
- **Share**: testshare (configurable)

Configuration is managed through the Python package's user-specific configuration system stored in `~/.config/smbreplay/config.pkl` on Linux/macOS or `%LOCALAPPDATA%\smbreplay\config.pkl` on Windows. This ensures each user can maintain their own private credentials and settings.

## Environment Setup

### Prerequisites

- Python 3.12+ (tested with Python 3.12.3)
- Linux/WSL2 environment
- Virtual environment support (`venv`)
- **tshark**: Wireshark command-line tool for packet capture analysis
- **capinfos**: Wireshark utility for PCAP file information (usually installed with tshark)
- **pcapfix**: PCAP file repair utility (for corrupted files)

### Installation

1. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install tshark pcapfix
   
   # Verify installations
   tshark -v
   pcapfix --help
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/SuperJT/smb2-replay.git
   cd smb2-replay
   ```

3. **Create and activate the virtual environment**:
   ```bash
   python3 -m venv venv --copies
   source venv/bin/activate
   ```

4. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Test the environment**:
   ```bash
   python test_environment.py
   ```

### Quick Start

1. **Set up trace directory** (optional):
   ```bash 
   export TRACES_FOLDER="~/cases"  # Default location
   mkdir -p "$TRACES_FOLDER"
   ```

2. **Activate the environment**:
   ```bash
   source activate_env.sh
   ```

## Usage Guide

### Step-by-Step Workflow

The SMB2 Replay tool follows a specific workflow to capture, analyze, and replay SMB2 network traffic. Follow these steps in order:

#### 1. **Check Your Configuration**
Before you can replay any PCAP files, you need to configure your target server settings:

```bash
# View your current configuration
smbreplay config show
```

This shows all your configuration options including server IP, domain, username, and share name. **You cannot replay a PCAP if you haven't identified which server to replay to in the configuration.**

#### 2. **List Available Traces**
Enumerate the available PCAP files in your traces directory:

```bash
# List traces in a specific case directory
smbreplay list traces --case 2010101010
```

This shows all PCAP files available in your traces directory (configured via the `TRACES_FOLDER` environment variable or `~/cases` by default).

#### 3. **Ingest a PCAP File**
Process a PCAP file to extract SMB2 sessions:

```bash
# Ingest a PCAP file (use quotes if filename has spaces or is in different directory)
smbreplay ingest --trace "My Capture File.pcap"
smbreplay ingest --trace /path/to/different/directory/capture.pcap
```

This extracts SMB2 sessions from the PCAP and stores them as Parquet files for analysis.

#### 4. **List SMB Sessions**
Once ingested, view all SMB2 sessions found in the PCAP:

```bash
# List all SMB sessions in the ingested PCAP
smbreplay session --list
```

This shows all session IDs that can be analyzed or replayed.

#### 5. **Analyze a Session**
View the commands and operations in a specific session:

```bash
# Display detailed session information
smbreplay session <session_id>

# Display brief table of commands (recommended for large sessions)
smbreplay session <session_id> --brief
```

Replace `<session_id>` with the actual session ID from step 4.

#### 6. **Replay the Session**
Execute the SMB2 operations on your target server:

```bash
# Replay the session to the configured target server
smbreplay replay <session_id>
```

This will connect to your configured server and replay all the SMB2 operations from the session.

### Complete Example

Here's a complete example workflow:

```bash
# 1. Check configuration
smbreplay config show

# 2. List available traces
smbreplay list traces --case 2010101010

# 3. Ingest a PCAP file
smbreplay ingest --trace "network_capture.pcap"

# 4. List sessions
smbreplay session --list

# 5. Analyze a session (brief format)
smbreplay session 0x7602000009fbdaa3 --brief

# 6. Replay the session
smbreplay replay 0x7602000009fbdaa3
```

### Configuration Management

#### View Current Configuration
```bash
smbreplay config show
```

#### Set Server Configuration
```bash
# Set target server details
smbreplay config set server_ip 192.168.1.100
smbreplay config set domain your-domain.local
smbreplay config set username your-username
smbreplay config set tree_name your-share-name
```

#### Set Case Management
```bash
# Set case ID and traces folder
smbreplay config set case_id 2010101010
smbreplay config set traces_folder ~/cases
```

### Command Reference

#### Configuration Commands
- `smbreplay config show` - Display current configuration
- `smbreplay config set <key> <value>` - Set configuration value
- `smbreplay config get <key>` - Get specific configuration value

#### Trace Management
- `smbreplay list traces --case <case_id>` - List available PCAP files
- `smbreplay ingest --trace <file.pcap>` - Process PCAP file

#### Session Analysis
- `smbreplay session --list` - List all SMB sessions
- `smbreplay session <session_id>` - Display session details
- `smbreplay session <session_id> --brief` - Display brief session summary

#### Replay Operations
- `smbreplay replay <session_id>` - Replay session to target server

### Important Notes

1. **Configuration First**: Always check your configuration with `smbreplay config show` before attempting replay
2. **File Paths**: Use quotes around filenames with spaces or special characters
3. **Session IDs**: Copy session IDs exactly as shown in the session list
4. **Brief Output**: Use `--brief` flag for large sessions to get a compact command summary
5. **Verbosity**: Add `-v`, `-vv`, or `-vvv` before commands for debug output
6. **Metadata Storage**: Processed session data is stored in `.tracer` directories within each case folder:
   ```
   ~/cases/2010101010/
   ├── .tracer/
   │   └── capture.pcap/
   │       └── sessions/
   │           ├── smb2_session_0x*.parquet    # Session data files
   │           └── session_metadata.json       # Session metadata
   └── capture.pcap                            # Original PCAP file
   ```

### Troubleshooting

- **"No configuration found"**: Run `smbreplay config show` and set required values
- **"No sessions found"**: Ensure PCAP file was ingested successfully
- **"Connection failed"**: Check server configuration and network connectivity
- **"File not found"**: Verify PCAP file path and use quotes for spaces 