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

# Import only lightweight components at package level
# Heavy imports are done lazily when needed
from .config import get_config, get_logger, set_verbosity

# Lazy import functions for heavy components
def _get_main():
    from .main import SMB2ReplaySystem, main
    return SMB2ReplaySystem, main

def _get_constants():
    from .constants import (
        SMB2_OP_NAME_DESC, 
        FSCTL_CONSTANTS, 
        FIELD_MAPPINGS, 
        check_tshark_availability
    )
    return SMB2_OP_NAME_DESC, FSCTL_CONSTANTS, FIELD_MAPPINGS, check_tshark_availability

def _get_ingestion():
    from .ingestion import run_ingestion, load_ingested_data, validate_ingested_data
    return run_ingestion, load_ingested_data, validate_ingested_data

def _get_session_manager():
    from .session_manager import get_session_manager, SessionManager
    return get_session_manager, SessionManager

def _get_replay():
    from .replay import replay_session, validate_operations, get_supported_commands
    return replay_session, validate_operations, get_supported_commands

def _get_utils():
    from .utils import (
        format_bytes, 
        format_duration, 
        Timer, 
        safe_json_serialize,
        get_file_info
    )
    return format_bytes, format_duration, Timer, safe_json_serialize, get_file_info

# Provide lazy access to heavy components
def __getattr__(name):
    """Lazy loading of heavy components."""
    if name == 'SMB2ReplaySystem':
        SMB2ReplaySystem, _ = _get_main()
        return SMB2ReplaySystem
    elif name == 'main':
        _, main = _get_main()
        return main
    elif name in ('SMB2_OP_NAME_DESC', 'FSCTL_CONSTANTS', 'FIELD_MAPPINGS', 'check_tshark_availability'):
        SMB2_OP_NAME_DESC, FSCTL_CONSTANTS, FIELD_MAPPINGS, check_tshark_availability = _get_constants()
        if name == 'SMB2_OP_NAME_DESC':
            return SMB2_OP_NAME_DESC
        elif name == 'FSCTL_CONSTANTS':
            return FSCTL_CONSTANTS
        elif name == 'FIELD_MAPPINGS':
            return FIELD_MAPPINGS
        elif name == 'check_tshark_availability':
            return check_tshark_availability
    elif name in ('run_ingestion', 'load_ingested_data', 'validate_ingested_data'):
        run_ingestion, load_ingested_data, validate_ingested_data = _get_ingestion()
        if name == 'run_ingestion':
            return run_ingestion
        elif name == 'load_ingested_data':
            return load_ingested_data
        elif name == 'validate_ingested_data':
            return validate_ingested_data
    elif name in ('get_session_manager', 'SessionManager'):
        get_session_manager, SessionManager = _get_session_manager()
        if name == 'get_session_manager':
            return get_session_manager
        elif name == 'SessionManager':
            return SessionManager
    elif name in ('replay_session', 'validate_operations', 'get_supported_commands'):
        replay_session, validate_operations, get_supported_commands = _get_replay()
        if name == 'replay_session':
            return replay_session
        elif name == 'validate_operations':
            return validate_operations
        elif name == 'get_supported_commands':
            return get_supported_commands
    elif name in ('format_bytes', 'format_duration', 'Timer', 'safe_json_serialize', 'get_file_info'):
        format_bytes, format_duration, Timer, safe_json_serialize, get_file_info = _get_utils()
        if name == 'format_bytes':
            return format_bytes
        elif name == 'format_duration':
            return format_duration
        elif name == 'Timer':
            return Timer
        elif name == 'safe_json_serialize':
            return safe_json_serialize
        elif name == 'get_file_info':
            return get_file_info
    
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

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

# Initialize logging when package is imported (but make it lazy)
def _init_logging():
    """Initialize logging lazily."""
    try:
        logger = get_logger()
        logger.debug(f"SMB2 Replay System v{__version__} initialized")
    except Exception as e:
        # Fallback in case logging setup fails
        import sys
        print(f"Warning: Failed to initialize logging: {e}", file=sys.stderr)
        print(f"SMB2 Replay System v{__version__} initialized with limited logging", file=sys.stderr)

# Call lazy logging initialization only when needed
def _ensure_logging():
    """Ensure logging is initialized."""
    global _logging_initialized
    if not hasattr(_ensure_logging, '_initialized'):
        _init_logging()
        _ensure_logging._initialized = True 