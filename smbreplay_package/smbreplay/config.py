"""
Configuration management for SMB2 Replay system.
Handles global configuration, logging setup, and persistence.
"""

import logging
import os
import pickle
import sys
from typing import List, Optional, TypedDict

# Default configurations
DEFAULT_PCAP_CONFIG = {"capture_path": None, "verbose_level": 0}  # Default to CRITICAL

DEFAULT_REPLAY_CONFIG = {
    "server_ip": "127.0.0.1",
    "port": 445,
    "domain": "",
    "username": "testuser",
    "password": "PASSWORD",
    "tree_name": "testshare",
    "max_wait": 5.0,
}

# Map verbosity levels (0–3) to logging levels
VERBOSITY_TO_LOGGING = {
    0: logging.CRITICAL,  # Only critical errors
    1: logging.INFO,  # Info and above
    2: logging.DEBUG,  # Debug and above
    3: logging.DEBUG,  # Same as 2, but can extend for finer granularity later
}


# Add a TypedDict for pcap_config to ensure correct types
class PcapConfig(TypedDict, total=False):
    capture_path: Optional[str]
    verbose_level: int


class ConfigManager:
    """Manages configuration settings and persistence."""

    def __init__(
        self, config_dir: Optional[str] = None, state_dir: Optional[str] = None
    ):
        """Initialize configuration manager.

        Args:
            config_dir: Directory to store config files. Defaults to user's home config directory.
            state_dir: Directory to store state files (logs). Defaults to XDG_STATE_HOME or ~/.local/state.
        """
        if config_dir is None:
            # Use user-specific config directory
            if os.name == "nt":  # Windows
                config_dir = os.path.expanduser("~\\AppData\\Local\\smbreplay")
            else:  # Unix-like systems
                config_dir = os.path.expanduser("~/.config/smbreplay")

        # Determine XDG_STATE_HOME for logs/state
        if state_dir is None:
            xdg_state_home = os.environ.get("XDG_STATE_HOME")
            if xdg_state_home:
                state_dir = os.path.join(
                    os.path.expanduser(xdg_state_home), "smbreplay"
                )
            else:
                state_dir = os.path.expanduser("~/.local/state/smbreplay")

        self.config_dir = config_dir
        self.state_dir = state_dir
        self.config_file = os.path.join(self.config_dir, "config.pkl")

        # Initialize configurations
        self.pcap_config: PcapConfig = DEFAULT_PCAP_CONFIG.copy()  # type: ignore
        self.replay_config = DEFAULT_REPLAY_CONFIG.copy()

        # Set up traces folder path (but don't create it yet)
        self.traces_folder: str = os.environ.get(
            "TRACES_FOLDER", os.path.expanduser("~/cases")
        )

        # Set up session output directory (for processed session data)
        # Defaults to traces_folder if not specified (backward compatible)
        self.session_output_dir: str = os.environ.get(
            "SESSION_OUTPUT_DIR", self.traces_folder
        )

        # Session management
        self.current_session_id: Optional[str] = None
        self.current_case_id: Optional[str] = os.environ.get(
            "DEFAULT_CASE_ID", "2010101010"
        )
        self.current_trace_name: Optional[str] = None

        # Lazy initialization flags
        self._config_loaded = False
        self._logger = None
        self._dirs_created = False
        self._state_dirs_created = False

        # Initialize other globals
        self.operations: List[dict] = []
        self.all_cells_run = False

    def _ensure_dirs_created(self):
        """Ensure config and traces directories are created (lazy initialization)."""
        if not self._dirs_created:
            os.makedirs(self.config_dir, exist_ok=True)
            os.makedirs(self.traces_folder, exist_ok=True)
            self._dirs_created = True

    def _ensure_state_dirs_created(self):
        """Ensure state (log) directory is created (lazy initialization)."""
        if not self._state_dirs_created:
            os.makedirs(self.state_dir, exist_ok=True)
            self._state_dirs_created = True

    def _ensure_config_loaded(self):
        """Ensure configuration is loaded (lazy initialization)."""
        if not self._config_loaded:
            self._load_config()
            self._config_loaded = True

    @property
    def logger(self):
        """Lazy-loaded logger property."""
        if self._logger is None:
            self._logger = self._setup_logging()
        return self._logger

    def _load_config(self):
        """Load configuration from pickle file if it exists."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "rb") as f:
                    loaded_config = pickle.load(f)

                if "pcap_config" in loaded_config:
                    self.pcap_config.update(
                        {
                            k: v
                            for k, v in loaded_config["pcap_config"].items()
                            if k in self.pcap_config
                        }
                    )

                if "replay_config" in loaded_config:
                    self.replay_config.update(
                        {
                            k: v
                            for k, v in loaded_config["replay_config"].items()
                            if k in self.replay_config
                        }
                    )

                # Load session management fields
                session_id = loaded_config.get("current_session_id")
                self.current_session_id = (
                    str(session_id) if session_id is not None else None
                )
                case_id = loaded_config.get("current_case_id")
                self.current_case_id = str(case_id) if case_id is not None else None
                trace_name = loaded_config.get("current_trace_name")
                self.current_trace_name = (
                    str(trace_name) if trace_name is not None else None
                )

                # Only print in debug mode to avoid noise
                if self.pcap_config.get("verbose_level", 0) >= 2:
                    print(f"Loaded config from {self.config_file}")

            except (pickle.PickleError, IOError) as e:
                # Only print errors in debug mode
                if self.pcap_config.get("verbose_level", 0) >= 1:
                    print(f"Failed to load {self.config_file}: {e}. Using defaults.")

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger("smbreplay")
        logger.handlers = []  # Clear existing handlers

        # Stream handler for stdout with broken pipe handling
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - [%(asctime)s] %(message)s",
                datefmt="%a %b %d %H:%M:%S %Y",
            )
        )

        # Add a filter to handle broken pipe errors gracefully
        class BrokenPipeFilter(logging.Filter):
            def filter(self, record):
                try:
                    return True
                except BrokenPipeError:
                    return False

        stream_handler.addFilter(BrokenPipeFilter())
        logger.addHandler(stream_handler)

        # File handler for persistent logs (create state dirs only when needed)
        self._ensure_state_dirs_created()
        log_file = os.path.join(self.state_dir, "smbreplay.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - [%(asctime)s] %(message)s",
                datefmt="%a %b %d %H:%M:%S %Y",
            )
        )
        logger.addHandler(file_handler)

        # Set logger level from pcap_config
        verbose_level = self.pcap_config.get("verbose_level", 0)
        logger.setLevel(
            VERBOSITY_TO_LOGGING.get(
                verbose_level if verbose_level is not None else 0, logging.CRITICAL
            )
        )

        return logger

    def save_config(self):
        """Save current configuration to pickle file."""
        self._ensure_dirs_created()  # Create dirs only when saving
        try:
            with open(self.config_file, "wb") as f:
                pickle.dump(
                    {
                        "pcap_config": self.pcap_config,
                        "replay_config": self.replay_config,
                        "current_session_id": self.current_session_id,
                        "current_case_id": self.current_case_id,
                        "current_trace_name": self.current_trace_name,
                    },
                    f,
                )
            self.logger.info(f"Saved config to {self.config_file}")
        except (pickle.PickleError, IOError) as e:
            self.logger.error(f"Failed to save {self.config_file}: {e}")

    def set_verbosity(self, level: int):
        """Set verbosity level and update logging."""
        self._ensure_config_loaded()  # Load config if needed
        self.pcap_config["verbose_level"] = level
        self.logger.setLevel(VERBOSITY_TO_LOGGING.get(level, logging.CRITICAL))
        self.save_config()
        self.logger.info(f"Updated verbosity to level {level}")

    def update_pcap_config(self, **kwargs):
        """Update PCAP configuration."""
        self._ensure_config_loaded()
        self.pcap_config.update(kwargs)
        self.save_config()

    def update_replay_config(self, **kwargs):
        """Update replay configuration."""
        self._ensure_config_loaded()
        self.replay_config.update(kwargs)
        self.save_config()

    def get_capture_path(self) -> Optional[str]:
        """Get current capture path."""
        self._ensure_config_loaded()
        value = self.pcap_config.get("capture_path")
        return str(value) if value is not None else None

    def set_capture_path(self, path: str):
        """Set capture path."""
        self._ensure_config_loaded()
        self.pcap_config["capture_path"] = str(path) if path is not None else None
        self.save_config()

    def get_traces_folder(self) -> str:
        """Get traces folder path."""
        return self.traces_folder

    def set_traces_folder(self, path: str):
        """Set traces folder path."""
        self.traces_folder = str(os.path.expanduser(path))
        # Only create the directory when it's actually needed
        self._dirs_created = False  # Reset flag to recreate dirs with new path
        self.save_config()

    def get_session_output_dir(self) -> str:
        """Get session output directory path."""
        return self.session_output_dir

    def set_session_output_dir(self, path: str):
        """Set session output directory path."""
        self.session_output_dir = str(os.path.expanduser(path))
        self._dirs_created = False  # Reset flag to recreate dirs with new path
        self.save_config()

    def get_verbosity_level(self) -> int:
        """Get current verbosity level."""
        self._ensure_config_loaded()
        value = self.pcap_config.get("verbose_level", 0)
        return int(value) if value is not None else 0

    def set_session_id(self, session_id: str) -> None:
        """Set the current session ID for analysis/replay."""
        self._ensure_config_loaded()
        self.current_session_id = session_id
        self.save_config()
        self.logger.info(f"Set session ID to {session_id}")

    def get_session_id(self) -> Optional[str]:
        """Get the current session ID."""
        self._ensure_config_loaded()
        return self.current_session_id

    def set_case_id(self, case_id: str) -> None:
        """Set the current case ID."""
        self._ensure_config_loaded()
        self.current_case_id = case_id
        self.save_config()
        self.logger.info(f"Set case ID to {case_id}")

    def validate_case_directory(self, case_id: Optional[str] = None) -> bool:
        """
        Validate and create the case directory if needed.

        Args:
            case_id: Specific case ID to validate. Defaults to current or '2010101010'.

        Returns:
            True if directory is valid and writable, False otherwise.
        """
        case_id = case_id or self.current_case_id or "2010101010"
        path = os.path.join(self.traces_folder, case_id)

        self._ensure_dirs_created()  # Ensure traces_folder exists

        if not os.path.exists(path):
            try:
                os.makedirs(path, exist_ok=True)
                self.logger.info(f"Created case directory: {path}")
            except OSError as e:
                self.logger.error(f"Failed to create {path}: {e}")
                return False

        if os.access(path, os.W_OK | os.R_OK):
            self.logger.info(f"Case directory validated: {path}")
            return True
        else:
            self.logger.error(f"Case directory not accessible: {path}")
            return False

    def get_case_id(self) -> Optional[str]:
        """Get the current case ID."""
        self._ensure_config_loaded()
        return self.current_case_id

    def set_trace_name(self, trace_name: str) -> None:
        """Set the current trace name."""
        self._ensure_config_loaded()
        self.current_trace_name = trace_name
        self.save_config()
        self.logger.info(f"Set trace name to {trace_name}")

    def get_trace_name(self) -> Optional[str]:
        """Get the current trace name."""
        self._ensure_config_loaded()
        return self.current_trace_name

    # Replay configuration methods
    def get_server_ip(self) -> str:
        """Get the replay server IP address."""
        self._ensure_config_loaded()
        value = self.replay_config.get("server_ip", "127.0.0.1")
        return str(value) if value is not None else "127.0.0.1"

    def set_server_ip(self, server_ip: str) -> None:
        """Set the replay server IP address."""
        self._ensure_config_loaded()
        self.replay_config["server_ip"] = server_ip
        self.save_config()
        self.logger.info(f"Set server IP to {server_ip}")

    def get_port(self) -> int:
        """Get the replay server port."""
        self._ensure_config_loaded()
        value = self.replay_config.get("port", 445)
        if isinstance(value, (int, float, str)):
            try:
                return int(value)
            except (TypeError, ValueError):
                return 445
        return 445

    def set_port(self, port: int) -> None:
        """Set the replay server port."""
        self._ensure_config_loaded()
        self.replay_config["port"] = port
        self.save_config()
        self.logger.info(f"Set port to {port}")

    def get_domain(self) -> str:
        """Get the replay server domain."""
        self._ensure_config_loaded()
        value = self.replay_config.get("domain", "")
        return str(value) if value is not None else ""

    def set_domain(self, domain: str) -> None:
        """Set the replay server domain."""
        self._ensure_config_loaded()
        self.replay_config["domain"] = domain
        self.save_config()
        self.logger.info(f"Set domain to {domain}")

    def get_username(self) -> str:
        """Get the replay server username."""
        self._ensure_config_loaded()
        value = self.replay_config.get("username", "testuser")
        return str(value) if value is not None else "testuser"

    def set_username(self, username: str) -> None:
        """Set the replay server username."""
        self._ensure_config_loaded()
        self.replay_config["username"] = username
        self.save_config()
        self.logger.info(f"Set username to {username}")

    def get_password(self) -> str:
        """Get the replay server password."""
        self._ensure_config_loaded()
        value = self.replay_config.get("password", "PASSWORD")
        return str(value) if value is not None else "PASSWORD"

    def set_password(self, password: str) -> None:
        """Set the replay server password."""
        self._ensure_config_loaded()
        self.replay_config["password"] = password
        self.save_config()
        self.logger.info(f"Set password to **********")

    def get_tree_name(self) -> str:
        """Get the replay server tree/share name."""
        self._ensure_config_loaded()
        value = self.replay_config.get("tree_name", "testshare")
        return str(value) if value is not None else "testshare"

    def set_tree_name(self, tree_name: str) -> None:
        """Set the replay server tree/share name."""
        self._ensure_config_loaded()
        self.replay_config["tree_name"] = tree_name
        self.save_config()
        self.logger.info(f"Set tree name to {tree_name}")

    def get_max_wait(self) -> float:
        """Get the replay server maximum wait time."""
        self._ensure_config_loaded()
        value = self.replay_config.get("max_wait", 5.0)
        if isinstance(value, (int, float, str)):
            try:
                return float(value)
            except (TypeError, ValueError):
                return 5.0
        return 5.0

    def set_max_wait(self, max_wait: float) -> None:
        """Set the replay server maximum wait time."""
        self._ensure_config_loaded()
        self.replay_config["max_wait"] = max_wait
        self.save_config()
        self.logger.info(f"Set max wait to {max_wait}")

    def resolve_session_file(self, session_id: str) -> Optional[str]:
        """Resolve a session ID to a session file path.

        Args:
            session_id: The session ID to resolve

        Returns:
            Path to the session file or None if not found
        """
        import glob

        # Get current case and trace from config
        case_id = self.get_case_id()
        trace_name = self.get_trace_name()

        if not case_id or not trace_name:
            self.logger.warning(
                "No case ID or trace name configured. Use 'config set' to configure them."
            )
            return None

        # Build the expected path pattern
        sessions_dir = os.path.join(
            self.traces_folder,
            case_id,
            ".tracer",
            trace_name.replace(".pcapng", ""),
            "sessions",
        )

        # Look for session files matching the session ID
        patterns = [
            f"smb2_session_{session_id}.parquet",
            f"smb2_session_*{session_id}*.parquet",
        ]

        for pattern in patterns:
            search_path = os.path.join(sessions_dir, pattern)
            matches = glob.glob(search_path)
            if matches:
                self.logger.info(f"Found session file: {matches[0]}")
                return matches[0]

        self.logger.warning(f"No session file found for session ID: {session_id}")
        return None


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def get_logger() -> logging.Logger:
    """Get the configured logger instance."""
    return get_config().logger


def get_traces_folder() -> str:
    """Get the traces folder path."""
    return get_config().traces_folder


def get_session_output_dir() -> str:
    """Get the session output directory path."""
    return get_config().session_output_dir


def set_verbosity(level: int):
    """Set global verbosity level."""
    get_config().set_verbosity(level)
