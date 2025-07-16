"""
SMB2 Replay System - A comprehensive tool for capturing, analyzing, and replaying SMB2 network traffic.

This package provides a complete solution for SMB2 protocol analysis including:
- PCAP file ingestion and parsing
- Session-based data organization
- Interactive analysis tools
- SMB2 operation replay capabilities
- Command-line interface

Main Components:
- config: Configuration management
- constants: SMB2 protocol constants and mappings
- tshark_processor: PCAP processing with tshark
- ingestion: Data ingestion and session extraction
- session_manager: Session management and operations
- replay: SMB2 session replay functionality
- main: Command-line interface and orchestration
- utils: Shared utility functions

Example Usage:
    # Command line usage
    python -m smbreplay ingest capture.pcap
    python -m smbreplay list
    python -m smbreplay analyze smb2_session_0x1234.parquet
    python -m smbreplay replay smb2_session_0x1234.parquet --server-ip 192.168.1.100
    
    # Python API usage
    from smbreplay import SMB2ReplaySystem
    
    system = SMB2ReplaySystem()
    system.setup_system()
    result = system.ingest_pcap("capture.pcap")
    sessions = system.list_sessions()
    operations = system.analyze_session(sessions[0])
    replay_result = system.replay_operations(operations)
"""

__version__ = "1.0.0"
__author__ = "SMB2 Replay System"
__description__ = "A comprehensive tool for capturing, analyzing, and replaying SMB2 network traffic"

# Import main components for public API
from .main import SMB2ReplaySystem, main
from .config import get_config, get_logger, set_verbosity
from .constants import (
    SMB2_OP_NAME_DESC, 
    FSCTL_CONSTANTS, 
    FIELD_MAPPINGS, 
    check_tshark_availability
)
from .ingestion import run_ingestion, load_ingested_data, validate_ingested_data
from .session_manager import get_session_manager, SessionManager
from .replay import replay_session, validate_operations, get_supported_commands
from .utils import (
    format_bytes, 
    format_duration, 
    Timer, 
    safe_json_serialize,
    get_file_info
)

# Define public API
__all__ = [
    # Main system
    'SMB2ReplaySystem',
    'main',
    
    # Configuration
    'get_config',
    'get_logger', 
    'set_verbosity',
    
    # Constants
    'SMB2_OP_NAME_DESC',
    'FSCTL_CONSTANTS',
    'FIELD_MAPPINGS',
    'check_tshark_availability',
    
    # Ingestion
    'run_ingestion',
    'load_ingested_data',
    'validate_ingested_data',
    
    # Session management
    'get_session_manager',
    'SessionManager',
    
    # Replay
    'replay_session',
    'validate_operations',
    'get_supported_commands',
    
    # Utilities
    'format_bytes',
    'format_duration',
    'Timer',
    'safe_json_serialize',
    'get_file_info',
    
    # Package info
    '__version__',
    '__author__',
    '__description__'
]

# Package-level configuration
def get_version():
    """Get package version."""
    return __version__

def get_package_info():
    """Get package information."""
    return {
        'name': 'smbreplay',
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'components': [
            'config', 'constants', 'tshark_processor', 'ingestion',
            'session_manager', 'replay', 'main', 'utils'
        ]
    }

# Initialize logging when package is imported
try:
    logger = get_logger()
    logger.debug(f"SMB2 Replay System v{__version__} initialized")
except Exception as e:
    # Fallback in case logging setup fails
    import sys
    print(f"Warning: Failed to initialize logging: {e}", file=sys.stderr)
    print(f"SMB2 Replay System v{__version__} initialized with limited logging", file=sys.stderr) 