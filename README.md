# SMB2 Replay System

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay/browse?at=refs%2Ftags%2Fv1.0.0)
[![Python](https://img.shields.io/badge/python-3.12+-green.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

A comprehensive system to capture, store, and replay SMB2 (Server Message Block version 2) network traffic for diagnostic, testing, and protocol analysis purposes in a controlled lab environment.



**Repository**: https://bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay/browse  
**Release**: [v1.0.0](RELEASE_NOTES_1.0.0.md) - Production Ready

---

## Installing from Bitbucket

To install or clone this repository, you must have access to the Bitbucket server. If your organization requires a personal access token (PAT), use it in place of your password when prompted.

### Clone with HTTPS and Personal Access Token

```bash
git clone https://<username>:<bitbucket-token>@bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay.git
cd smbreplay
```

Replace `<username>` with your Bitbucket username and `<bitbucket-token>` with your personal access token. If you have 2FA enabled, a token is required.

---

## Project Overview

### Objective
Develop a system to capture, store, and replay SMB2 network traffic for diagnostic, testing, and protocol interaction analysis, critical for file sharing in Windows-based systems.

### Approach
- **Capture**: Extract SMB2 packets from PCAP files using local `tshark`
- **Storage**: Store data in Parquet files by session (`smb2.sesid`) with JSON metadata
- **Replay**: Replicate file operations using `smbprotocol` library on a lab server
- **Analysis**: Python package with CLI and programmatic interfaces for automation
- **Development**: Modular design with separate components for different functionalities


Configuration is managed through the Python package's user-specific configuration system stored in `~/.config/smbreplay/config.pkl` on Linux/macOS or `%LOCALAPPDATA%\smbreplay\config.pkl` on Windows. This ensures each user can maintain their own private credentials and settings.

## Environment Setup

For detailed installation instructions, see [INSTALLATION.md](INSTALLATION.md).

### Prerequisites

- Python 3.12+ (tested with Python 3.12.3)
- Linux/WSL2 environment
- Virtual environment support (`venv`)
- **tshark**: Wireshark command-line tool for packet capture analysis
- **capinfos**: Wireshark utility for PCAP file information (usually installed with tshark)
- **pcapfix**: PCAP file repair utility (for corrupted files)

### Quick Installation


**Option 1: Interactive Installation (Recommended)**
```bash
git clone https://<username>:<bitbucket-token>@bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay.git
cd smbreplay
python3 -m venv venv --copies
source venv/bin/activate
python install.py  # Interactive installer
```

**Option 2: Manual Installation**
1. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install tshark pcapfix
   
   # Verify installations
   tshark -v
   pcapfix --help
   ```

2. **Clone and install**:
   ```bash
   git clone https://<username>:<bitbucket-token>@bitbucket.ngage.netapp.com/users/jtownsen/repos/smbreplay.git
   cd smbreplay
   python3 -m venv venv --copies
   source venv/bin/activate
   
   # Basic installation (recommended for new users)
   pip install -e .
   
   # Or with development tools (for developers)
   pip install -e .[dev-tools]
   ```

3. **Test the environment**:
   ```bash
   python smbreplay_package/smbreplay/test_environment.py
   ```

### Quick Start

1. **Set up trace directory** (optional):
   ```bash
   export TRACES_FOLDER="~/cases"  # Default location
   mkdir -p "$TRACES_FOLDER"
   ```

2. **Activate the environment**:
   ```bash
   source venv/bin/activate
   ```

### Testing with a Local SMB Server (Docker)

For quick testing without a production SMB server:

```bash
# 1. Start a test SMB container (uses port 1445 to avoid conflicts)
docker run -d --name smb-test \
  -p 1445:445 \
  -v /tmp/smb-share:/share \
  dperson/samba \
  -u "testuser;testpass" \
  -s "testshare;/share;yes;no;no;testuser;testuser;testuser" \
  -p

# 2. Configure smbreplay for the test server
smbreplay config set server_ip 127.0.0.1
smbreplay config set port 1445
smbreplay config set username testuser
smbreplay config set password testpass
smbreplay config set tree_name testshare

# 3. Verify configuration
smbreplay config show

# 4. Test the full workflow
smbreplay list traces --case test-data
smbreplay ingest --trace small/smb-on-windows-10.pcapng
smbreplay session --list
smbreplay replay <session_id>

# 5. Verify files were created
smbclient //127.0.0.1/testshare -p 1445 -U testuser%testpass -c 'ls'

# 6. Clean up when done
docker stop smb-test && docker rm smb-test
```

### Development Tools (Optional)

If you installed with development tools (`pip install -e .[dev-tools]`), you have access to additional utilities:

```bash
# Test SMB connectivity to your configured server
python utils/tests/test_smb_connectivity.py

# Clean up test files from SMB server
python utils/cleanup/cleanup_test_files.py

# Run comprehensive test suite
python utils/tests/run_tests.py

# Advanced analysis tools
python utils/analysis/setup_workflow_state.py
```

**Note**: Development tools are not required for basic SMB2 replay functionality. They provide additional testing, debugging, and analysis capabilities for advanced users and developers.

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

Example output:
```
Current Configuration:
  Traces folder: /home/user/cases
  Capture path: /home/user/cases/2010101010/capture.pcap
  Verbosity level: 0
  Session ID: 0x000000002a16df11
  Case ID: 2010101010
  Trace name: capture.pcap
  Server IP: 192.168.1.100
  Port: 445
  Domain:
  Username: testuser
  Password: ***
  Tree name: testshare
  Max wait: 5.0
```

#### Set Server Configuration
```bash
# Set target server details
smbreplay config set server_ip 192.168.1.100
smbreplay config set port 445              # Custom port (default: 445)
smbreplay config set domain your-domain.local
smbreplay config set username your-username
smbreplay config set password your-password
smbreplay config set tree_name your-share-name
```

#### Set Case Management
```bash
# Set case ID and traces folder
smbreplay config set case_id 2010101010
smbreplay config set traces_folder ~/cases
```

#### Available Configuration Keys
| Key | Description | Default |
|-----|-------------|---------|
| `server_ip` | Target SMB server IP address | `127.0.0.1` |
| `port` | Target SMB server port | `445` |
| `domain` | SMB domain (optional) | `` |
| `username` | SMB authentication username | `testuser` |
| `password` | SMB authentication password | `PASSWORD` |
| `tree_name` | SMB share name to connect to | `testshare` |
| `max_wait` | Connection timeout in seconds | `5.0` |
| `case_id` | Current case identifier | `2010101010` |
| `traces_folder` | Root folder for PCAP files | `~/cases` |

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

#### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "No configuration found" | First-time setup | Run `smbreplay config show` and set required values |
| "No sessions found" | PCAP not ingested | Run `smbreplay ingest --trace <file>` first |
| "Connection failed" | Server unreachable | Check `server_ip`, `port`, and network connectivity |
| "File not found" | Invalid path | Use quotes for paths with spaces: `--trace "My File.pcap"` |
| "Permission denied" on `.tracer/` | Directory owned by root | Fix ownership: `sudo chown -R $USER:$USER ~/cases` |

#### Port 445 Already in Use (WSL2/Windows)

On Windows or WSL2, port 445 is typically used by the Windows SMB service. To test against a local Docker container:

```bash
# Run SMB container on alternate port
docker run -d --name smb-test \
  -p 1445:445 \
  -v /tmp/smb-share:/share \
  dperson/samba \
  -u "testuser;testpass" \
  -s "testshare;/share;yes;no;no;testuser;testuser;testuser" \
  -p

# Configure smbreplay to use the alternate port
smbreplay config set port 1445
smbreplay config set server_ip 127.0.0.1
smbreplay config set username testuser
smbreplay config set password testpass
smbreplay config set tree_name testshare

# Verify connectivity
smbclient -L //127.0.0.1 -p 1445 -U testuser%testpass
```

#### Virtual Environment Issues

If you encounter "bad interpreter" errors after moving the project:

```bash
# Recreate the virtual environment
rm -rf venv
python3 -m venv venv --copies
source venv/bin/activate
pip install -e smbreplay_package/
```

The `--copies` flag ensures Python binaries are copied rather than symlinked, which improves portability.

#### Permission Issues with `.tracer` Directories

If ingestion fails with "Permission denied" on `.tracer` directories:

```bash
# Check ownership
ls -la ~/cases/<case_id>/.tracer/

# Fix ownership if needed
sudo chown -R $USER:$USER ~/cases/<case_id>/.tracer/

# Or use a different case directory you own
smbreplay config set case_id my-test-case
```

#### Debugging with Verbose Output

Add `-v` flags for more detailed output:

```bash
smbreplay -v replay <session_id>      # INFO level
smbreplay -vv replay <session_id>     # DEBUG level
smbreplay -vvv replay <session_id>    # Maximum verbosity
```

## Development and Project Management

### Agentic Tools Integration

This project uses [Agentic Tools](https://github.com/agentic-tools/agentic-tools) for intelligent project management and development workflow automation. The integration provides:

- **Project Organization**: Structured task management with dependencies and priorities
- **Progress Tracking**: Real-time progress monitoring and milestone tracking
- **Intelligent Recommendations**: AI-powered task recommendations based on current state
- **Memory Management**: Persistent knowledge storage for project context
- **Research Integration**: Automated research capabilities for technical decisions

### Development Workflow

The project follows a structured development workflow:

1. **Task Management**: Tasks are organized with priorities, complexity estimates, and dependencies
2. **Quality Assurance**: Automated testing, linting, and code quality checks
3. **Documentation**: Comprehensive documentation with examples and guides
4. **Release Management**: Structured release process with changelog and release notes

### Contributing

1. **Fork the repository** and create a feature branch
2. **Follow the coding standards** and ensure all tests pass
3. **Update documentation** for any new features or changes
4. **Submit a pull request** with detailed description of changes

### Testing

Run the test suite to ensure everything is working:

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=smbreplay

# Run specific test categories
python -m pytest smbreplay_package/smbreplay/  # Core package tests
python -m pytest utils/tests/                  # Utility tests
```

## REST API and TypeScript SDK

For programmatic access and Next.js integration, smbreplay provides a REST API and TypeScript SDK.

### REST API

The FastAPI-based REST API wraps the SMB2ReplaySystem for HTTP access:

```bash
# Install API dependencies
pip install -r requirements-api.txt

# Run the API server
uvicorn api.main:app --host 0.0.0.0 --port 3004
```

**API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/info` | GET | System information |
| `/api/config` | GET/PUT | Configuration management |
| `/api/traces` | GET | List trace files |
| `/api/traces/ingest` | POST | Ingest PCAP file |
| `/api/sessions` | GET | List sessions |
| `/api/sessions/{id}` | GET | Get session operations |
| `/api/replay/validate` | POST | Validate replay readiness |
| `/api/replay/setup` | POST | Setup infrastructure |
| `/api/replay/execute` | POST | Execute replay |

Interactive API documentation available at `/docs` (Swagger) or `/redoc`.

### TypeScript SDK

Type-safe client for Next.js and Node.js applications:

```bash
cd sdk
npm install
npm run build
```

**Usage:**
```typescript
import { SMBReplayClient } from '@smbreplay/sdk';

const client = new SMBReplayClient({ baseUrl: 'http://localhost:3004' });

// Health check
const health = await client.healthCheck();

// List sessions
const sessions = await client.listSessions();

// Execute replay
const result = await client.executeReplay('0x1234567890abcdef', {
  server_ip: '192.168.1.100',
  validate_first: true,
});
```

### Docker Deployment

Build and run the API in Docker:

```bash
# Build the image
docker build -t smbreplay-api .

# Run the container
docker run -d \
  -p 3004:3004 \
  -v ~/cases:/stingray:ro \
  -e TRACES_FOLDER=/stingray \
  smbreplay-api
```

For integration with the tracer docker-compose, see `docker-compose.smbreplay.yml`.

### Running Tests

```bash
# Python API tests
pip install pytest pytest-asyncio httpx
pytest api/tests/

# TypeScript SDK tests
cd sdk
npm install
npm test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- SMB protocol community for technical guidance
- Open source contributors and testers
- Agentic Tools for intelligent project management 