"""Service wrapper for SMB2ReplaySystem.

This module provides a clean interface to the SMB2ReplaySystem class,
handling initialization, configuration, and error handling.
"""

import logging
import os
import sys
from functools import lru_cache
from typing import Any, Dict, List, Optional

# Add the smbreplay package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "smbreplay_package"))

from smbreplay.main import SMB2ReplaySystem
from smbreplay.config import get_config

logger = logging.getLogger(__name__)


class SMBReplayServiceError(Exception):
    """Base exception for SMBReplayService errors."""

    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code
        super().__init__(message)


class SMBReplayService:
    """Service wrapper for SMB2ReplaySystem with async job support."""

    def __init__(self):
        """Initialize the service."""
        self._system: Optional[SMB2ReplaySystem] = None
        self._initialized = False

    @property
    def system(self) -> SMB2ReplaySystem:
        """Get or create the SMB2ReplaySystem instance."""
        if self._system is None:
            self._system = SMB2ReplaySystem()
            self._system.setup_system()
            self._initialized = True
        return self._system

    def ensure_full_setup(self) -> bool:
        """Ensure full system setup including tshark check."""
        return self.system.setup_system_full()

    # =========================================================================
    # Health & Info
    # =========================================================================

    def health_check(self) -> Dict[str, Any]:
        """Perform a health check.

        Returns:
            Dict with status, version, and tshark availability.
        """
        try:
            info = self.system.get_system_info()
            return {
                "status": "ok" if info.get("tshark_available", False) else "degraded",
                "version": "1.0.0",
                "tshark_available": info.get("tshark_available", False),
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "error",
                "version": "1.0.0",
                "tshark_available": False,
            }

    def get_system_info(self) -> Dict[str, Any]:
        """Get detailed system information.

        Returns:
            Dict with system configuration and status.
        """
        info = self.system.get_system_info()
        return {
            "version": "1.0.0",
            "tshark_available": info.get("tshark_available", False),
            "capture_path": info.get("capture_path"),
            "capture_valid": info.get("capture_valid", False),
            "supported_commands": info.get("supported_commands", {}),
            "traces_folder": info.get("traces_folder", ""),
            "verbosity_level": info.get("verbosity_level", 0),
            "packet_count": info.get("packet_count"),
        }

    # =========================================================================
    # Configuration
    # =========================================================================

    def get_config(self) -> Dict[str, Any]:
        """Get current configuration.

        Returns:
            Dict with all configuration values.
        """
        config = self.system.config
        password = config.get_password()

        return {
            "traces_folder": config.get_traces_folder(),
            "capture_path": config.get_capture_path(),
            "verbosity_level": config.get_verbosity_level(),
            "session_id": config.get_session_id(),
            "case_id": config.get_case_id(),
            "trace_name": config.get_trace_name(),
            "server_ip": config.get_server_ip(),
            "port": config.get_port(),
            "domain": config.get_domain(),
            "username": config.get_username(),
            "password_set": password != "PASSWORD" and password != "",
            "tree_name": config.get_tree_name(),
            "max_wait": config.get_max_wait(),
        }

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update configuration values.

        Args:
            updates: Dict of config keys to new values.

        Returns:
            Updated configuration dict.
        """
        config = self.system.config

        if "traces_folder" in updates and updates["traces_folder"] is not None:
            config.set_traces_folder(updates["traces_folder"])

        if "capture_path" in updates and updates["capture_path"] is not None:
            config.set_capture_path(updates["capture_path"])

        if "verbosity_level" in updates and updates["verbosity_level"] is not None:
            self.system.set_verbosity(updates["verbosity_level"])

        if "session_id" in updates and updates["session_id"] is not None:
            config.set_session_id(updates["session_id"])

        if "case_id" in updates and updates["case_id"] is not None:
            config.set_case_id(updates["case_id"])

        if "trace_name" in updates and updates["trace_name"] is not None:
            config.set_trace_name(updates["trace_name"])

        # Replay config updates
        replay_updates = {}
        if "server_ip" in updates and updates["server_ip"] is not None:
            replay_updates["server_ip"] = updates["server_ip"]
        if "port" in updates and updates["port"] is not None:
            replay_updates["port"] = updates["port"]
        if "domain" in updates and updates["domain"] is not None:
            replay_updates["domain"] = updates["domain"]
        if "username" in updates and updates["username"] is not None:
            replay_updates["username"] = updates["username"]
        if "password" in updates and updates["password"] is not None:
            replay_updates["password"] = updates["password"]
        if "tree_name" in updates and updates["tree_name"] is not None:
            replay_updates["tree_name"] = updates["tree_name"]
        if "max_wait" in updates and updates["max_wait"] is not None:
            replay_updates["max_wait"] = updates["max_wait"]

        if replay_updates:
            self.system.configure_replay(**replay_updates)

        return self.get_config()

    def get_config_value(self, key: str) -> Optional[str]:
        """Get a single configuration value.

        Args:
            key: Configuration key name.

        Returns:
            Configuration value as string, or None if not set.
        """
        config = self.system.config

        key_map = {
            "traces_folder": config.get_traces_folder,
            "capture_path": config.get_capture_path,
            "verbosity_level": lambda: str(config.get_verbosity_level()),
            "session_id": config.get_session_id,
            "case_id": config.get_case_id,
            "trace_name": config.get_trace_name,
            "server_ip": config.get_server_ip,
            "port": lambda: str(config.get_port()),
            "domain": config.get_domain,
            "username": config.get_username,
            "tree_name": config.get_tree_name,
            "max_wait": lambda: str(config.get_max_wait()),
        }

        if key in key_map:
            value = key_map[key]()
            return str(value) if value is not None else None

        raise SMBReplayServiceError(f"Unknown configuration key: {key}", code="INVALID_KEY")

    # =========================================================================
    # Traces
    # =========================================================================

    def list_traces(self, case_id: Optional[str] = None) -> List[Dict[str, str]]:
        """List available trace files.

        Args:
            case_id: Optional case ID to list traces for.

        Returns:
            List of trace file info dicts.
        """
        traces = self.system.list_traces(case_id)
        effective_case_id = case_id or self.system.config.get_case_id()

        return [
            {
                "path": trace,
                "name": os.path.basename(trace),
                "case_id": effective_case_id,
            }
            for trace in traces
        ]

    def ingest_pcap(
        self,
        path: str,
        force: bool = False,
        reassembly: bool = False,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest a PCAP file synchronously.

        Args:
            path: Path to PCAP file.
            force: Force re-ingestion.
            reassembly: Enable TCP reassembly.
            case_id: Optional case ID for relative paths.

        Returns:
            Ingestion result dict.
        """
        # Resolve path if relative
        if not os.path.isabs(path):
            if case_id:
                self.system.config.set_case_id(case_id)
            traces_folder = self.system.config.get_traces_folder()
            effective_case_id = case_id or self.system.config.get_case_id()
            if effective_case_id:
                path = os.path.join(traces_folder, effective_case_id, path)

        # Security: Validate path doesn't escape allowed directories
        traces_folder = self.system.config.get_traces_folder()
        real_path = os.path.realpath(path)
        real_traces = os.path.realpath(traces_folder)
        if not real_path.startswith(real_traces + os.sep) and real_path != real_traces:
            raise SMBReplayServiceError(
                f"Path traversal detected: path must be within traces folder",
                code="PATH_TRAVERSAL"
            )

        result = self.system.ingest_pcap(
            path, force_reingest=force, reassembly=reassembly
        )

        if result:
            return {
                "success": True,
                "sessions": result.get("sessions", []),
                "session_count": len(result.get("sessions", [])),
                "total_frames": result.get("total_frames"),
                "processing_time": result.get("processing_time"),
            }
        else:
            return {
                "success": False,
                "sessions": [],
                "session_count": 0,
                "error": "Ingestion failed",
            }

    # =========================================================================
    # Sessions
    # =========================================================================

    def list_sessions(self, capture_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """List available sessions.

        Args:
            capture_path: Optional capture path override.

        Returns:
            List of session summary dicts.
        """
        sessions = self.system.list_sessions(capture_path)

        return [
            {
                "session_id": self._extract_session_id(session),
                "file_name": session,
                "operation_count": None,  # Would need to load session to get this
            }
            for session in sessions
        ]

    def get_session_operations(
        self,
        session_id: str,
        capture_path: Optional[str] = None,
        file_filter: Optional[str] = None,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Get operations for a session.

        Args:
            session_id: Session ID or file name.
            capture_path: Optional capture path override.
            file_filter: Optional file path filter.
            fields: Optional list of fields to include.

        Returns:
            Dict with session_id, operations list, and metadata.
        """
        # Normalize session ID to file name
        session_file = self._normalize_session_file(session_id)

        operations = self.system.get_session_info(
            session_file,
            capture_path=capture_path,
            file_filter=file_filter,
            fields=fields,
        )

        if operations is None:
            raise SMBReplayServiceError(
                f"Failed to load session: {session_id}", code="SESSION_NOT_FOUND"
            )

        return {
            "session_id": session_id,
            "operations": operations,
            "total": len(operations),
            "file_filter": file_filter,
        }

    # =========================================================================
    # Replay
    # =========================================================================

    def validate_replay(
        self,
        session_id: str,
        capture_path: Optional[str] = None,
        file_filter: Optional[str] = None,
        check_fs: bool = True,
        check_ops: bool = True,
    ) -> Dict[str, Any]:
        """Validate replay readiness.

        Args:
            session_id: Session ID to validate.
            capture_path: Optional capture path override.
            file_filter: Optional file path filter.
            check_fs: Check file system structure.
            check_ops: Check operation validity.

        Returns:
            Validation result dict.
        """
        session_file = self._normalize_session_file(session_id)

        operations = self.system.get_session_info(
            session_file, capture_path=capture_path, file_filter=file_filter
        )

        if operations is None:
            raise SMBReplayServiceError(
                f"Failed to load session: {session_id}", code="SESSION_NOT_FOUND"
            )

        return self.system.validate_replay_readiness(
            operations, check_fs=check_fs, check_ops=check_ops
        )

    def setup_infrastructure(
        self,
        session_id: str,
        capture_path: Optional[str] = None,
        file_filter: Optional[str] = None,
        dry_run: bool = False,
        force: bool = False,
        server_overrides: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Setup file system infrastructure for replay.

        Args:
            session_id: Session ID to setup for.
            capture_path: Optional capture path override.
            file_filter: Optional file path filter.
            dry_run: Show what would be created without changes.
            force: Continue despite errors.
            server_overrides: Optional server configuration overrides.

        Returns:
            Setup result dict.
        """
        session_file = self._normalize_session_file(session_id)

        # Apply server overrides if provided
        if server_overrides:
            self.system.configure_replay(**server_overrides)

        operations = self.system.get_session_info(
            session_file, capture_path=capture_path, file_filter=file_filter
        )

        if operations is None:
            raise SMBReplayServiceError(
                f"Failed to load session: {session_id}", code="SESSION_NOT_FOUND"
            )

        return self.system.setup_file_system_infrastructure(
            operations, dry_run=dry_run, force=force
        )

    def execute_replay(
        self,
        session_id: str,
        capture_path: Optional[str] = None,
        file_filter: Optional[str] = None,
        validate_first: bool = True,
        enable_ping: bool = True,
        server_overrides: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute a replay operation.

        Args:
            session_id: Session ID to replay.
            capture_path: Optional capture path override.
            file_filter: Optional file path filter.
            validate_first: Validate before replaying.
            enable_ping: Ping server before starting.
            server_overrides: Optional server configuration overrides.

        Returns:
            Replay result dict.
        """
        session_file = self._normalize_session_file(session_id)

        # Apply server overrides if provided
        if server_overrides:
            self.system.configure_replay(**server_overrides)

        operations = self.system.get_session_info(
            session_file, capture_path=capture_path, file_filter=file_filter
        )

        if operations is None:
            raise SMBReplayServiceError(
                f"Failed to load session: {session_id}", code="SESSION_NOT_FOUND"
            )

        # Validate if requested
        if validate_first:
            validation = self.system.validate_replay_readiness(operations)
            if not validation.get("ready", False):
                return {
                    "success": False,
                    "total_operations": len(operations),
                    "successful_operations": 0,
                    "failed_operations": 0,
                    "errors": ["Validation failed"],
                    "validation": validation,
                }

        # Configure ping
        try:
            from smbreplay.replay import get_replayer
            replayer = get_replayer()
            replayer.set_ping_enabled(enable_ping)
        except Exception as e:
            logger.warning(f"Could not configure ping: {e}")

        return self.system.replay_operations(operations)

    # =========================================================================
    # Helpers
    # =========================================================================

    def _normalize_session_file(self, session_id: str) -> str:
        """Normalize session ID to file name format.

        Args:
            session_id: Session ID or file name.

        Returns:
            Session file name.
        """
        if session_id.endswith(".parquet"):
            return session_id
        return f"smb2_session_{session_id}.parquet"

    def _extract_session_id(self, session_file: str) -> str:
        """Extract session ID from file name.

        Args:
            session_file: Session file name.

        Returns:
            Session ID.
        """
        if session_file.startswith("smb2_session_") and session_file.endswith(".parquet"):
            return session_file.replace("smb2_session_", "").replace(".parquet", "")
        return session_file


@lru_cache(maxsize=1)
def get_smbreplay_service() -> SMBReplayService:
    """Get the singleton SMBReplayService instance.

    Returns:
        SMBReplayService instance.
    """
    return SMBReplayService()
