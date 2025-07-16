"""
Configuration management for SMB2 Replay system.
Handles global configuration, logging setup, and persistence.
"""

import os
import sys
import pickle
import logging
from typing import Dict, Any, Optional

# Default configurations
DEFAULT_PCAP_CONFIG = {
    "capture_path": None,
    "verbose_level": 0  # Default to CRITICAL
}

DEFAULT_REPLAY_CONFIG = {
    "server_ip": "10.216.29.241",
    "domain": "nas-deep.local",
    "username": "jtownsen",
    "password": "PASSWORD",
    "tree_name": "2pm",
    "max_wait": 5.0
}

# Map verbosity levels (0–3) to logging levels
VERBOSITY_TO_LOGGING = {
    0: logging.CRITICAL,  # Only critical errors
    1: logging.INFO,      # Info and above
    2: logging.DEBUG,     # Debug and above
    3: logging.DEBUG      # Same as 2, but can extend for finer granularity later
}


class ConfigManager:
    """Manages configuration settings and persistence."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_dir: Directory to store config files. Defaults to user's home config directory.
        """
        if config_dir is None:
            # Use user-specific config directory
            if os.name == 'nt':  # Windows
                config_dir = os.path.expanduser('~\\AppData\\Local\\smbreplay')
            else:  # Unix-like systems
                config_dir = os.path.expanduser('~/.config/smbreplay')
        
        self.config_dir = config_dir
        os.makedirs(self.config_dir, exist_ok=True)
        self.config_file = os.path.join(self.config_dir, "config.pkl")
        
        # Initialize configurations
        self.pcap_config = DEFAULT_PCAP_CONFIG.copy()
        self.replay_config = DEFAULT_REPLAY_CONFIG.copy()
        
        # Set up traces folder
        self.traces_folder = os.environ.get('TRACES_FOLDER', os.path.expanduser('~/cases'))
        os.makedirs(self.traces_folder, exist_ok=True)
        
        # Session management
        self.current_session_id = None
        self.current_case_id = None
        self.current_trace_name = None
        
        # Load existing configuration
        self._load_config()
        
        # Initialize logging
        self.logger = self._setup_logging()
        
        # Initialize other globals
        self.operations = []
        self.all_cells_run = False
        
    def _load_config(self):
        """Load configuration from pickle file if it exists."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'rb') as f:
                    loaded_config = pickle.load(f)
                    
                if 'pcap_config' in loaded_config:
                    self.pcap_config.update({
                        k: v for k, v in loaded_config['pcap_config'].items() 
                        if k in self.pcap_config
                    })
                    
                if 'replay_config' in loaded_config:
                    self.replay_config.update({
                        k: v for k, v in loaded_config['replay_config'].items() 
                        if k in self.replay_config
                    })
                
                # Load session management fields
                self.current_session_id = loaded_config.get('current_session_id')
                self.current_case_id = loaded_config.get('current_case_id')
                self.current_trace_name = loaded_config.get('current_trace_name')
                    
                # Only print in debug mode to avoid noise
                if self.pcap_config.get('verbose_level', 0) >= 2:
                    print(f"Loaded config from {self.config_file}")
                
            except (pickle.PickleError, IOError) as e:
                # Only print errors in debug mode
                if self.pcap_config.get('verbose_level', 0) >= 1:
                    print(f"Failed to load {self.config_file}: {e}. Using defaults.")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('smbreplay')
        logger.handlers = []  # Clear existing handlers
        
        # Stream handler for stdout
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(asctime)s] %(message)s', 
            datefmt='%a %b %d %H:%M:%S %Y'
        ))
        logger.addHandler(stream_handler)
        
        # File handler for persistent logs
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        log_file = os.path.join(self.config_dir, 'smbreplay.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(asctime)s] %(message)s', 
            datefmt='%a %b %d %H:%M:%S %Y'
        ))
        logger.addHandler(file_handler)
        
        # Set logger level from pcap_config
        logger.setLevel(VERBOSITY_TO_LOGGING.get(
            self.pcap_config.get("verbose_level", 0), 
            logging.CRITICAL
        ))
        
        return logger
    
    def save_config(self):
        """Save current configuration to pickle file."""
        try:
            with open(self.config_file, 'wb') as f:
                pickle.dump({
                    'pcap_config': self.pcap_config,
                    'replay_config': self.replay_config,
                    'current_session_id': self.current_session_id,
                    'current_case_id': self.current_case_id,
                    'current_trace_name': self.current_trace_name
                }, f)
            self.logger.info(f"Saved config to {self.config_file}")
        except (pickle.PickleError, IOError) as e:
            self.logger.error(f"Failed to save {self.config_file}: {e}")
    
    def set_verbosity(self, level: int):
        """Set verbosity level and update logging."""
        self.pcap_config["verbose_level"] = level
        self.logger.setLevel(VERBOSITY_TO_LOGGING.get(level, logging.CRITICAL))
        self.save_config()
        self.logger.info(f"Updated verbosity to level {level}")
    
    def update_pcap_config(self, **kwargs):
        """Update PCAP configuration."""
        self.pcap_config.update(kwargs)
        self.save_config()
    
    def update_replay_config(self, **kwargs):
        """Update replay configuration."""
        self.replay_config.update(kwargs)
        self.save_config()
    
    def get_capture_path(self) -> Optional[str]:
        """Get current capture path."""
        return self.pcap_config.get("capture_path")
    
    def set_capture_path(self, path: str):
        """Set capture path."""
        self.pcap_config["capture_path"] = path
        self.save_config()
    
    def get_traces_folder(self) -> str:
        """Get traces folder path."""
        return self.traces_folder
    
    def set_traces_folder(self, path: str):
        """Set traces folder path."""
        self.traces_folder = os.path.expanduser(path)
        os.makedirs(self.traces_folder, exist_ok=True)
        self.save_config()
    
    def get_verbosity_level(self) -> int:
        """Get current verbosity level."""
        return self.pcap_config.get('verbose_level', 0)

    def set_session_id(self, session_id: str) -> None:
        """Set the current session ID for analysis/replay."""
        self.current_session_id = session_id
        self.save_config()
        self.logger.info(f"Set session ID to {session_id}")

    def get_session_id(self) -> Optional[str]:
        """Get the current session ID."""
        return self.current_session_id

    def set_case_id(self, case_id: str) -> None:
        """Set the current case ID."""
        self.current_case_id = case_id
        self.save_config()
        self.logger.info(f"Set case ID to {case_id}")

    def get_case_id(self) -> Optional[str]:
        """Get the current case ID."""
        return self.current_case_id

    def set_trace_name(self, trace_name: str) -> None:
        """Set the current trace name."""
        self.current_trace_name = trace_name
        self.save_config()
        self.logger.info(f"Set trace name to {trace_name}")

    def get_trace_name(self) -> Optional[str]:
        """Get the current trace name."""
        return self.current_trace_name

    # Replay configuration methods
    def get_server_ip(self) -> str:
        """Get the replay server IP address."""
        return self.replay_config.get("server_ip", "10.216.29.241")

    def set_server_ip(self, server_ip: str) -> None:
        """Set the replay server IP address."""
        self.replay_config["server_ip"] = server_ip
        self.save_config()
        self.logger.info(f"Set server IP to {server_ip}")

    def get_domain(self) -> str:
        """Get the replay server domain."""
        return self.replay_config.get("domain", "nas-deep.local")

    def set_domain(self, domain: str) -> None:
        """Set the replay server domain."""
        self.replay_config["domain"] = domain
        self.save_config()
        self.logger.info(f"Set domain to {domain}")

    def get_username(self) -> str:
        """Get the replay server username."""
        return self.replay_config.get("username", "jtownsen")

    def set_username(self, username: str) -> None:
        """Set the replay server username."""
        self.replay_config["username"] = username
        self.save_config()
        self.logger.info(f"Set username to {username}")

    def get_password(self) -> str:
        """Get the replay server password."""
        return self.replay_config.get("password", "PASSWORD")

    def set_password(self, password: str) -> None:
        """Set the replay server password."""
        self.replay_config["password"] = password
        self.save_config()
        self.logger.info(f"Set password to {password}")

    def get_tree_name(self) -> str:
        """Get the replay server tree/share name."""
        return self.replay_config.get("tree_name", "2pm")

    def set_tree_name(self, tree_name: str) -> None:
        """Set the replay server tree/share name."""
        self.replay_config["tree_name"] = tree_name
        self.save_config()
        self.logger.info(f"Set tree name to {tree_name}")

    def get_max_wait(self) -> float:
        """Get the replay server maximum wait time."""
        return self.replay_config.get("max_wait", 5.0)

    def set_max_wait(self, max_wait: float) -> None:
        """Set the replay server maximum wait time."""
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
            self.logger.warning("No case ID or trace name configured. Use 'config set' to configure them.")
            return None
            
        # Build the expected path pattern
        sessions_dir = os.path.join(self.traces_folder, case_id, '.tracer', trace_name.replace('.pcapng', ''), 'sessions')
        
        # Look for session files matching the session ID
        patterns = [
            f"smb2_session_{session_id}.parquet",
            f"smb2_session_*{session_id}*.parquet"
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
_config_manager = None


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


def set_verbosity(level: int):
    """Set global verbosity level."""
    get_config().set_verbosity(level)