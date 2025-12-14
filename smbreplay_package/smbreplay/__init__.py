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
__description__ = (
    "A comprehensive tool for capturing, analyzing, and replaying SMB2 network traffic"
)

# Import only lightweight components at package level
# Heavy imports are done lazily when needed
from .config import get_config, get_logger, set_verbosity


# Lazy import functions for heavy components
def _get_main():
    from .main import SMB2ReplaySystem, main

    return SMB2ReplaySystem, main


def _get_constants():
    from .constants import (
        FIELD_MAPPINGS,
        FSCTL_CONSTANTS,
        SMB2_OP_NAME_DESC,
        check_tshark_availability,
    )

    return SMB2_OP_NAME_DESC, FSCTL_CONSTANTS, FIELD_MAPPINGS, check_tshark_availability


def _get_ingestion():
    from .ingestion import load_ingested_data, run_ingestion, validate_ingested_data

    return run_ingestion, load_ingested_data, validate_ingested_data


def _get_session_manager():
    from .session_manager import SessionManager, get_session_manager

    return get_session_manager, SessionManager


def _get_replay():
    from .replay import get_supported_commands, replay_session, validate_operations

    return replay_session, validate_operations, get_supported_commands


def _get_utils():
    from .utils import (
        Timer,
        format_bytes,
        format_duration,
        get_file_info,
        safe_json_serialize,
    )

    return format_bytes, format_duration, Timer, safe_json_serialize, get_file_info


# Provide lazy access to heavy components
def __getattr__(name):
    """Lazy loading of heavy components."""
    if name == "SMB2ReplaySystem":
        SMB2ReplaySystem, _ = _get_main()
        return SMB2ReplaySystem
    elif name == "main":
        _, main = _get_main()
        return main
    elif name in (
        "SMB2_OP_NAME_DESC",
        "FSCTL_CONSTANTS",
        "FIELD_MAPPINGS",
        "check_tshark_availability",
    ):
        (
            SMB2_OP_NAME_DESC,
            FSCTL_CONSTANTS,
            FIELD_MAPPINGS,
            check_tshark_availability,
        ) = _get_constants()
        return {
            "SMB2_OP_NAME_DESC": SMB2_OP_NAME_DESC,
            "FSCTL_CONSTANTS": FSCTL_CONSTANTS,
            "FIELD_MAPPINGS": FIELD_MAPPINGS,
            "check_tshark_availability": check_tshark_availability,
        }[name]
    elif name in ("run_ingestion", "load_ingested_data", "validate_ingested_data"):
        run_ingestion, load_ingested_data, validate_ingested_data = _get_ingestion()
        return {
            "run_ingestion": run_ingestion,
            "load_ingested_data": load_ingested_data,
            "validate_ingested_data": validate_ingested_data,
        }[name]
    elif name in ("get_session_manager", "SessionManager"):
        get_session_manager, SessionManager = _get_session_manager()
        return {
            "get_session_manager": get_session_manager,
            "SessionManager": SessionManager,
        }[name]
    elif name in ("replay_session", "validate_operations", "get_supported_commands"):
        replay_session, validate_operations, get_supported_commands = _get_replay()
        return {
            "replay_session": replay_session,
            "validate_operations": validate_operations,
            "get_supported_commands": get_supported_commands,
        }[name]
    elif name in (
        "format_bytes",
        "format_duration",
        "Timer",
        "safe_json_serialize",
        "get_file_info",
    ):
        format_bytes, format_duration, Timer, safe_json_serialize, get_file_info = (
            _get_utils()
        )
        return {
            "format_bytes": format_bytes,
            "format_duration": format_duration,
            "Timer": Timer,
            "safe_json_serialize": safe_json_serialize,
            "get_file_info": get_file_info,
        }[name]

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# Define public API
__all__ = [
    "FIELD_MAPPINGS",
    "FSCTL_CONSTANTS",
    # Constants
    "SMB2_OP_NAME_DESC",
    # Main system
    "SMB2ReplaySystem",
    "SessionManager",
    "Timer",
    "__author__",
    "__description__",
    # Package info
    "__version__",
    "check_tshark_availability",
    # Utilities
    "format_bytes",
    "format_duration",
    # Configuration
    "get_config",
    "get_file_info",
    "get_logger",
    # Session management
    "get_session_manager",
    "get_supported_commands",
    "load_ingested_data",
    "main",
    # Replay
    "replay_session",
    # Ingestion
    "run_ingestion",
    "safe_json_serialize",
    "set_verbosity",
    "validate_ingested_data",
    "validate_operations",
]


# Package-level configuration
def get_version():
    """Get package version."""
    return __version__


def get_package_info():
    """Get package information."""
    return {
        "name": "smbreplay",
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "components": [
            "config",
            "constants",
            "tshark_processor",
            "ingestion",
            "session_manager",
            "replay",
            "main",
            "utils",
        ],
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
        print(
            f"SMB2 Replay System v{__version__} initialized with limited logging",
            file=sys.stderr,
        )


# Call lazy logging initialization only when needed
def _ensure_logging():
    """Ensure logging is initialized."""
    if not hasattr(_ensure_logging, "_initialized"):
        _init_logging()
        _ensure_logging._initialized = True
