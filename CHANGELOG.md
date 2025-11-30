# Changelog

All notable changes to the SMB2 Replay project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-07-22

### Added
- **Core SMB2 Replay System**: Complete implementation for capturing, analyzing, and replaying SMB2 network traffic
- **PCAP Ingestion**: Extract SMB2 sessions from PCAP files using tshark integration
- **Session Management**: Organize and analyze SMB2 sessions with detailed metadata
- **SMB2 Operation Replay**: Replay SMB2 operations to target servers using smbprotocol library
- **Command Line Interface**: Comprehensive CLI with subcommands for all major operations
- **Configuration Management**: User-specific configuration system with secure credential storage
- **Performance Monitoring**: Real-time performance tracking and optimization
- **Data Storage**: Parquet-based storage system for efficient session data management
- **Protocol Support**: Full SMB2 protocol support including file operations, directory management, and session handling

### Features
- **Ingestion Pipeline**: Process PCAP files to extract SMB2 sessions with field mapping and normalization
- **Session Analysis**: Detailed session analysis with command summaries and operation tracking
- **Replay Engine**: Robust replay system with error handling and validation
- **CLI Commands**:
  - `smbreplay config` - Configuration management
  - `smbreplay ingest` - PCAP file processing
  - `smbreplay list` - Trace and session enumeration
  - `smbreplay session` - Session analysis and display
  - `smbreplay replay` - SMB2 operation replay
  - `smbreplay setup` - System setup and validation
  - `smbreplay validate` - Pre-trace validation
  - `smbreplay info` - System information

### Technical Implementation
- **Modular Architecture**: Clean separation of concerns with dedicated modules for each component
- **Type Safety**: Full type hints and MyPy compliance
- **Error Handling**: Comprehensive error handling with detailed logging
- **Performance Optimization**: Optimized data processing with pandas and pyarrow
- **Testing**: Extensive test suite with 49 test cases covering core functionality
- **Documentation**: Comprehensive README with step-by-step usage guide

### Dependencies
- **Core**: pandas>=2.0.0, pyarrow>=10.0.0, numpy>=1.24.0
- **SMB Protocol**: smbprotocol>=1.8.0
- **Network**: paramiko>=3.0.0, scapy>=2.5.0
- **System**: psutil>=5.9.0
- **CLI**: click>=8.0.0, python-dotenv>=1.0.0
- **Testing**: pytest>=7.0.0, pytest-cov>=4.0.0

### System Requirements
- **Python**: 3.8+ (tested with Python 3.12.3)
- **OS**: Linux/WSL2 (primary), Windows/macOS (compatible)
- **System Tools**: tshark, pcapfix
- **Memory**: 4GB+ RAM recommended for large PCAP files
- **Storage**: Parquet-based storage with efficient compression

### Installation
```bash
# Clone repository
git clone https://github.com/SuperJT/smb2-replay.git
cd smb2-replay

# Install system dependencies
sudo apt update && sudo apt install tshark pcapfix

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install package
cd smbreplay_package
pip install -e .
```

### Quick Start
```bash
# Configure target server
smbreplay config set server_ip 192.168.1.100
smbreplay config set domain your-domain.local
smbreplay config set username your-username
smbreplay config set tree_name your-share-name

# Process PCAP file
smbreplay ingest --trace "capture.pcap"

# List sessions
smbreplay session --list

# Analyze session
smbreplay session <session_id> --brief

# Replay session
smbreplay replay <session_id>
```

### Known Issues
- Some utility tests may show warnings (non-critical)
- SMB encryption requirements may vary by server configuration
- Large PCAP files (>1GB) may require significant memory

### Future Enhancements
- SMB3 protocol support
- Web-based interface
- Real-time capture and replay
- Advanced filtering and search capabilities
- Integration with SIEM systems
- Automated testing framework

---

## [Unreleased]

### Planned
- Enhanced error recovery mechanisms
- Additional protocol support
- Performance optimizations
- Extended documentation 