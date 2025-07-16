# SMB2 Replay Project

This project provides a system to capture, store, and replay SMB2 (Server Message Block version 2) network traffic for diagnostic, testing, and protocol analysis purposes in a controlled lab environment.

## Project Overview

### Objective
Develop a system to capture, store, and replay SMB2 network traffic for diagnostic, testing, and protocol interaction analysis, critical for file sharing in Windows-based systems.

### Approach
- **Capture**: Extract SMB2 packets from PCAP files using local `tshark`
- **Storage**: Store data in Parquet files by session (`smb2.sesid`) with JSON metadata
- **Replay**: Replicate file operations using `impacket` library on a lab server
- **Analysis**: Python package with CLI and programmatic interfaces for automation
- **Development**: Modular design with separate components for different functionalities

### Lab Server Configuration
- **IP**: 10.216.29.241 (configurable)
- **Domain**: nas-deep.local (configurable)
- **Username**: jtownsen (configurable)
- **Share**: 2pm (configurable)

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

2. **Clone/Navigate to the project directory**:
   ```bash
   cd /path/to/smbreplay
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

## Usage

### Python Package Interface

The system is implemented as a well-structured Python package for programmatic use and automation.

#### Package Structure

```
smbreplay_package/
└── smbreplay/
    ├── __init__.py          # Package initialization
    ├── __main__.py          # CLI entry point
    ├── config.py            # Configuration management
    ├── constants.py         # SMB2 constants and mappings
    ├── tshark_processor.py  # PCAP processing with tshark
    ├── ingestion.py         # Data ingestion and storage
    ├── session_manager.py   # Session management and filtering
    ├── replay.py            # SMB2 replay functionality
    ├── main.py              # Main CLI interface
    ├── utils.py             # Utility functions
    └── test_conversion.py   # Package verification tests
```

#### Using the Python Package

1. **Import the package**:
   ```python
   from smbreplay import SMBReplaySystem, Config, SessionManager, ReplayEngine
   ```

2. **Basic usage example**:
   ```python
   # Initialize the system
   config = Config()
   config.set_traces_folder("~/cases")
   config.set_server_config(
       server_ip="10.216.29.241",
       domain="nas-deep.local",
       username="jtownsen",
       password="your_password",
       tree_name="2pm"
   )
   
   # Create system instance
   system = SMBReplaySystem(config)
   
   # Process a PCAP file
   case_number = "001"
   pcap_path = "/path/to/your/capture.pcap"
   system.ingest_pcap(case_number, pcap_path)
   
   # List available sessions
   sessions = system.list_sessions(case_number)
   print(f"Found {len(sessions)} sessions")
   
   # Load a specific session
   session_data = system.load_session(case_number, sessions[0])
   
   # Replay operations
   replay_engine = ReplayEngine(config)
   replay_engine.replay_session(session_data)
   ```

3. **Command-line interface**:
   ```bash
   # Navigate to package directory
   cd smbreplay_package
   
   # Show help
   python -m smbreplay --help
   
   # Show system info
   python -m smbreplay info
   
   # Configure the system
   python -m smbreplay config set server_ip 192.168.1.100
   python -m smbreplay config set case_id 2010101010
   
   # Process a PCAP file with debug output
   python -m smbreplay -vv ingest --case 2010101010 --trace tcpdump_properly_fixed.pcap
   
   # List available sessions
   python -m smbreplay list sessions --case 2010101010
   
   # Display session information
   python -m smbreplay session 0x7602000009fbdaa3 --case 2010101010 --trace tcpdump_properly_fixed.pcap
   
   # Display session with brief output
   python -m smbreplay session 0x7602000009fbdaa3 --case 2010101010 --trace tcpdump_properly_fixed.pcap --brief
   
   # Replay a session
   python -m smbreplay replay 0x7602000009fbdaa3 --case 2010101010 --trace tcpdump_properly_fixed.pcap
   ```

#### Package Features

- **Modular Design**: Separate modules for different functionalities
- **User-Specific Configuration**: Private configuration stored in user's home directory
- **Session Management**: Load, filter, and analyze SMB2 sessions with session ID resolution
- **Replay Engine**: Execute SMB2 operations on target server with impacket integration
- **CLI Interface**: Command-line tools for automation with debug verbosity support
- **Error Handling**: Comprehensive error handling and logging
- **Testing**: Built-in tests for package verification
- **Brief Output**: Compact session display format for large files
- **Protocol Support**: Complete SMB2 protocol constants and field mappings for impacket

### Configuration

#### User-Specific Configuration

The system uses a user-specific configuration file stored locally for security:

- **Linux/macOS**: `~/.config/smbreplay/config.pkl`
- **Windows**: `%LOCALAPPDATA%\smbreplay\config.pkl`

This ensures that each user can maintain their own private credentials and settings without sharing them with other users.

#### Configuration Commands

Configure the system using the CLI:

```bash
# View current configuration
python -m smbreplay config show

# Set replay server configuration
python -m smbreplay config set server_ip 192.168.1.100
python -m smbreplay config set domain your-domain.local
python -m smbreplay config set username your-username
python -m smbreplay config set password your-password
python -m smbreplay config set tree_name your-share-name

# Set case management
python -m smbreplay config set case_id 2010101010
python -m smbreplay config set traces_folder ~/cases

# Get specific configuration value
python -m smbreplay config get server_ip
```

#### Replay Server Settings

The following settings are available for replay configuration:

- `server_ip`: Target SMB server IP address
- `domain`: SMB domain name
- `username`: SMB username
- `password`: SMB password (stored securely in user config)
- `tree_name`: SMB share/tree name
- `max_wait`: Maximum wait time for operations (default: 5.0 seconds)

#### Debug Verbosity

Control debug output using verbosity flags:

```bash
# Basic operation (CRITICAL level only)
python -m smbreplay ingest --case 001 --trace file.pcap

# Error level output
python -m smbreplay -v ingest --case 001 --trace file.pcap

# Debug level output (recommended for troubleshooting)
python -m smbreplay -vv ingest --case 001 --trace file.pcap

# Maximum verbosity
python -m smbreplay -vvv ingest --case 001 --trace file.pcap
```

Note: The verbosity flag (`-v`, `-vv`, `-vvv`) must come **before** the subcommand name.

#### Environment Variables

The project uses the following environment variables:

- `TRACES_FOLDER`: Directory for trace data storage (defaults to `~/cases`)
- `TSHARK_PATH`: Path to tshark executable (defaults to 'tshark')

#### Configuration Files

- `~/.config/smbreplay/config.pkl`: User-specific configuration (Linux/macOS)
- `%LOCALAPPDATA%\smbreplay\config.pkl`: User-specific configuration (Windows)

#### Traces Directory Structure

The system creates and manages a configurable traces directory structure:

```
~/cases/                           # Default TRACES_FOLDER location
├── 2010101010/                    # Case-specific directories
│   ├── .tracer/                   # Processing metadata
│   │   └── tcpdump_properly_fixed/
│   │       └── sessions/          # Session parquet files
│   │           ├── smb2_session_0x*.parquet
│   │           └── session_metadata.json
│   └── trace_files.pcap           # Original trace files
└── case_002/
    └── ...
```
```

## Key Features

### SMB2 Protocol Support
- Comprehensive SMB2 field capture (619 fields)
- Session-based data organization by `smb2.sesid`
- Command mapping for all SMB2 operations (0-18)
- NT status code interpretation
- Tree ID and File ID mapping

### PCAP Processing
- Automatic PCAP corruption detection and repair using `pcapfix`
- Memory-efficient processing with streaming
- Zstd compression for Parquet storage
- Metadata extraction and validation

### Replay Capabilities
- **Implemented Commands**: Tree Connect (3), Create (5), Close (6), Read (8), Write (9)
- **Pre-trace State Setup**: Automatic directory and file creation
- **TID/FID Mapping**: Maintains relationships between original and replayed sessions
- **Error Handling**: Comprehensive error handling and session management

## Workflow Examples

### Example 1: Analyze SMB2 Traffic from PCAP

```bash
# Using the CLI interface with debug output
python -m smbreplay -vv ingest --case 2010101010 --trace tcpdump_properly_fixed.pcap

# List available sessions
python -m smbreplay list sessions --case 2010101010

# Display session information
python -m smbreplay session 0x7602000009fbdaa3 --case 2010101010 --trace tcpdump_properly_fixed.pcap

# Display session with brief output for large files
python -m smbreplay session 0x7602000009fbdaa3 --case 2010101010 --trace tcpdump_properly_fixed.pcap --brief
```

### Example 2: Configure and Replay File Operations

```bash
# Configure replay server settings
python -m smbreplay config set server_ip 192.168.1.100
python -m smbreplay config set domain your-domain.local
python -m smbreplay config set username your-username
python -m smbreplay config set password your-password
python -m smbreplay config set tree_name your-share-name

# Replay a session
python -m smbreplay replay 0x7602000009fbdaa3 --case 2010101010 --trace tcpdump_properly_fixed.pcap
```

### Example 3: Batch Processing Multiple PCAPs

```bash
#!/bin/bash
# Using the CLI interface with proper case management

# Set up case directory
python -m smbreplay config set case_id 2010101010

for pcap in /evidence/*.pcap; do
    pcap_name=$(basename "$pcap")
    echo "Processing $pcap_name"
    
    # Process with debug output
    python -m smbreplay -vv ingest --case 2010101010 --trace "$pcap_name"
    
    # List sessions for this trace
    python -m smbreplay list sessions --case 2010101010 --trace "$pcap_name"
done
```

## Troubleshooting

### WSL2 Issues

If you encounter file system issues with WSL2:

1. Ensure virtual environment is created with `--copies` flag
2. Check that all dependencies installed successfully
3. Run `python test_environment.py` to verify setup

### Missing Dependencies

If packages fail to import:

1. Activate the virtual environment: `source venv/bin/activate`
2. Reinstall requirements: `pip install -r requirements.txt`
3. For impacket issues, try: `pip install impacket --no-deps`

### Tshark Issues

If tshark commands fail:

1. Verify tshark installation: `tshark -v`
2. Check permissions for packet capture
3. Set custom tshark path: `export TSHARK_PATH="/path/to/tshark"`

### PCAP Corruption Issues

If you encounter corrupted PCAP files:

1. Install pcapfix: `sudo apt install -y pcapfix`
2. Repair the PCAP: `pcapfix -d -t 276 -o output.pcap input.pcap`
3. Update configuration to use the repaired file

### Package Import Issues

If the Python package fails to import:

1. Ensure you're in the correct directory: `cd smbreplay_package`
2. Check Python path: `python -c "import sys; print(sys.path)"`
3. Run package tests: `python -m smbreplay.test_conversion`

## Project Structure

```
~/bin/smbreplay/                        # Project root directory
├── venv/                               # Virtual environment
├── smbreplay_package/                  # Python package directory
│   └── smbreplay/                      # Main Python package
│       ├── __init__.py                 # Package initialization
│       ├── __main__.py                 # CLI entry point
│       ├── config.py                   # Configuration management
│       ├── constants.py                # SMB2 constants
│       ├── tshark_processor.py         # PCAP processing
│       ├── ingestion.py                # Data ingestion
│       ├── session_manager.py          # Session management
│       ├── replay.py                   # Replay functionality
│       ├── main.py                     # Main CLI interface
│       ├── utils.py                    # Package utilities
│       └── test_conversion.py          # Package tests
├── utils/                              # Development/debug utilities
│   ├── check_tree_connect_frames.py   # Debug script for tree connects
│   ├── compare_pcap_parquet.py         # PCAP to parquet comparison tool
│   └── debug_tree_connects.py          # Tree connect debugging script
├── requirements.txt                    # Python dependencies
├── activate_env.sh                     # Environment activation script
├── test_environment.py                 # Environment verification script
├── smbreplay.log                       # Application logs
└── README.md                           # This file
```

## Development Notes

- **Architecture**: Modular Python package for automation and analysis
- **SMB2 Analysis**: Complete protocol analysis with 619 field capture capability
- **Session Storage**: Organized by `smb2.sesid` in Parquet format with zstd compression
- **Local Processing**: Uses local `tshark` instead of remote SSH connections
- **Configuration**: Centralized configuration management
- **Replay Capability**: Core SMB2 commands implemented (Tree Connect, Create, Close, Read, Write)
- **Error Handling**: Comprehensive PCAP corruption handling with `pcapfix` integration
- **Environment**: Configurable via `TRACES_FOLDER` environment variable

## Recent Updates

- **User-Specific Configuration**: Configuration files now stored in user's home directory (`~/.config/smbreplay/` on Linux/macOS, `%LOCALAPPDATA%\smbreplay\` on Windows) for security and privacy
- **Session ID Resolution**: Bare session IDs now work without requiring full filename prefix/suffix
- **Debug Verbosity**: Added `-v`, `-vv`, `-vvv` flags for different levels of debug output during ingestion and processing
- **Brief Output Format**: Added `--brief` option for compact session display suitable for large files
- **Protocol Constants**: Complete SMB2 protocol constants and field mappings for impacket integration
- **Replay Server Configuration**: Full configuration management for replay server settings with secure credential storage
- **Error Handling**: Improved error handling with proper identification of non-SMB2 traces (e.g., LDAP traffic)
- **Case Management**: Enhanced case and trace file management with proper path resolution
- **CLI Interface**: Improved command-line interface with better help and examples
- **Package Architecture**: Modular design with separate components for different functionalities 