# SMB2 Replay Project

This project provides a system to capture, store, and replay SMB2 (Server Message Block version 2) network traffic for diagnostic, testing, and protocol analysis purposes.

## Project Overview

- **Capture**: Extract SMB2 packets from PCAP files using `ntap-tshark`
- **Storage**: Store data in Parquet files by session with JSON metadata
- **Replay**: Replicate file operations using `impacket` library
- **Analysis**: Interactive Jupyter notebook interface for configuration and analysis

## Environment Setup

### Prerequisites

- Python 3.12+ (tested with Python 3.12.3)
- Linux/WSL2 environment
- Virtual environment support (`venv`)

### Installation

1. **Clone/Navigate to the project directory**:
   ```bash
   cd /path/to/smbreplay
   ```

2. **Create and activate the virtual environment**:
   ```bash
   python3 -m venv venv --copies
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Test the environment**:
   ```bash
   python test_environment.py
   ```

### Quick Start

1. **Activate the environment**:
   ```bash
   source activate_env.sh
   ```

2. **Launch Jupyter Lab**:
   ```bash
   jupyter lab
   ```

3. **Open the main notebook**:
   - Navigate to `impacket.ipynb`
   - Start working with SMB2 traffic analysis

### Environment Variables

The project uses the following environment variables:

- `TRACES_FOLDER`: Set to `~/cases` for local trace data (also mapped to `/stingray` in containers)

### Lab Server Configuration

The project is configured to work with a test lab server:

- **IP**: 10.216.29.241
- **Domain**: nas-deep.local
- **Username**: jtownsen
- **Share**: 2pm

Configuration is stored in `config.pkl` and can be modified through the notebook interface.

## Key Dependencies

- **impacket**: SMB protocol implementation
- **pandas**: Data manipulation and analysis
- **pyarrow**: Parquet file support
- **paramiko**: SSH connections
- **scapy**: Network packet analysis
- **jupyter**: Interactive notebook environment
- **ipywidgets**: Interactive UI components

## Usage

### Environment Management

- **Activate environment**: `source activate_env.sh`
- **Deactivate environment**: `deactivate`
- **Test environment**: `python test_environment.py`

### Jupyter Operations

- **Launch Jupyter Lab**: `jupyter lab`
- **Launch Jupyter Notebook**: `jupyter notebook`
- **Access notebook**: Open `impacket.ipynb`

### Container vs Local Development

This project was originally designed for containerized environments but has been adapted for local development. The notebook contains container-specific paths that may need adjustment for your local environment.

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

## Project Structure

```
smbreplay/
├── venv/                 # Virtual environment
├── impacket.ipynb        # Main analysis notebook
├── requirements.txt      # Python dependencies
├── activate_env.sh       # Environment activation script
├── test_environment.py   # Environment verification script
└── README.md            # This file
```

## Development Notes

- The project is designed for SMB2 protocol analysis and replay
- Sessions are stored by `smb2.sesid` in Parquet format
- Interactive UI uses `ipywidgets` for configuration
- Logging is configured for both console and file output 