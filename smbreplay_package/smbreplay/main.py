"""
Main entry point for SMB2 Replay System.
Orchestrates all components and provides a command-line interface.
"""

import argparse
import sys
import os
from typing import Optional, List, Dict, Any

from .config import get_config, get_logger, set_verbosity
from .constants import check_tshark_availability
from .ingestion import run_ingestion, load_ingested_data, validate_ingested_data
from .session_manager import get_session_manager
from .replay import replay_session, validate_operations, get_supported_commands
from .tshark_processor import validate_pcap_file, get_packet_count

logger = get_logger()


class SMB2ReplaySystem:
    """Main orchestrator for the SMB2 replay system."""
    
    def __init__(self):
        self.config = get_config()
        self.session_manager = get_session_manager()
        
    def setup_system(self) -> bool:
        """Set up and validate the system environment.
        
        Returns:
            True if setup successful, False otherwise
        """
        logger.info("Setting up SMB2 replay system")
        
        # Check tshark availability
        if not check_tshark_availability():
            logger.critical("tshark is not available. Please install Wireshark/tshark")
            return False
        
        logger.info("System setup completed successfully")
        return True
    
    def ingest_pcap(self, pcap_path: str, force_reingest: bool = False, 
                   reassembly: bool = False, verbose: bool = False) -> Optional[Dict[str, Any]]:
        """Ingest a PCAP file for analysis.
        
        Args:
            pcap_path: Path to PCAP file
            force_reingest: Force re-ingestion even if data exists
            reassembly: Enable TCP reassembly
            verbose: Enable verbose logging
            
        Returns:
            Dictionary with ingestion results or None if failed
        """
        logger.info(f"Ingesting PCAP file: {pcap_path}")
        
        # Validate PCAP file
        if not validate_pcap_file(pcap_path):
            logger.error(f"Invalid PCAP file: {pcap_path}")
            return None
        
        # Set capture path in config
        self.config.set_capture_path(pcap_path)
        
        # Status callback for progress updates
        def status_callback(message: str):
            logger.info(f"Ingestion Status: {message}")
        
        # Run ingestion
        result = run_ingestion(
            capture_path=pcap_path,
            reassembly_enabled=reassembly,
            force_reingest=force_reingest,
            verbose=verbose,
            status_callback=status_callback
        )
        
        if result and validate_ingested_data(result):
            logger.info("PCAP ingestion completed successfully")
            return result
        else:
            logger.error("PCAP ingestion failed")
            return None
    
    def list_sessions(self, capture_path: Optional[str] = None) -> List[str]:
        """List available sessions for analysis.
        
        Args:
            capture_path: Optional path to capture file
            
        Returns:
            List of session file names
        """
        if capture_path:
            self.config.set_capture_path(capture_path)
        
        capture_path = capture_path or self.config.get_capture_path()
        if not capture_path:
            logger.error("No capture path configured")
            return []
        
        output_dir = self.session_manager.get_output_directory(capture_path)
        if not output_dir:
            logger.error("Could not determine output directory")
            return []
        
        return self.session_manager.list_session_files(output_dir)
    
    def list_traces(self) -> List[str]:
        """List available trace files in the traces folder.
        
        Returns:
            List of validated trace file names (PCAP files)
        """
        traces_folder = self.config.get_traces_folder()
        case_id = self.config.get_case_id()
        
        # Require case_id to be configured for list traces
        if not case_id:
            logger.error("Case ID must be configured to list traces. Use 'smbreplay config set case_id <case_id>'")
            return []
        
        # If case_id is configured, look in traces_folder/case_id/
        search_folder = os.path.join(traces_folder, case_id)
        
        if not os.path.exists(search_folder):
            logger.warning(f"Case folder does not exist: {search_folder}")
            return []
        
        trace_files = []
        try:
            for root, dirs, files in os.walk(search_folder):
                for file in files:
                    if file.lower().endswith(('.pcap', '.pcapng', '.trc', '.trc0')):
                        # Get full path for validation
                        full_path = os.path.join(root, file)
                        
                        # Validate the PCAP file using tshark
                        if validate_pcap_file(full_path):
                            # Get relative path from search folder
                            relative_path = os.path.relpath(full_path, search_folder)
                            trace_files.append(relative_path)
                        else:
                            logger.debug(f"Skipping invalid PCAP file: {full_path}")
        except Exception as e:
            logger.error(f"Error listing traces: {e}")
            return []
        
        return sorted(trace_files)
    
    def get_session_info(self, session_file: str, capture_path: Optional[str] = None,
                       file_filter: Optional[str] = None, 
                       fields: Optional[List[str]] = None) -> Optional[List[Dict[str, Any]]]:
        """Get session information for a specific session.
        
        Args:
            session_file: Name of the session file
            capture_path: Optional path to capture file
            file_filter: Optional file filter
            fields: Optional list of fields to include
            
        Returns:
            List of operations or None if failed
        """
        if capture_path:
            self.config.set_capture_path(capture_path)
        
        capture_path = capture_path or self.config.get_capture_path()
        if not capture_path:
            logger.error("No capture path configured")
            return None
        
        logger.info(f"Analyzing session: {session_file}")
        
        # Load session data
        session_frames, field_options, file_options, selected_fields = \
            self.session_manager.load_and_summarize_session(capture_path, session_file)
        
        if session_frames is None:
            logger.error(f"Failed to load session: {session_file}")
            return None
        
        # Use provided fields or defaults
        if fields:
            selected_fields = [f for f in fields if f in field_options]
        
        # Update operations
        operations = self.session_manager.update_operations(
            capture_path, session_file, file_filter, selected_fields
        )
        
        logger.info(f"Analyzed session {session_file}: {len(operations)} operations")
        return operations
    
    def replay_operations(self, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Replay a list of operations.
        
        Args:
            operations: List of operation dictionaries
            
        Returns:
            Dictionary with replay results
        """
        logger.info(f"Replaying {len(operations)} operations")
        
        # Validate operations
        validation = validate_operations(operations)
        if not validation["valid"]:
            logger.error(f"Operation validation failed: {validation['issues']}")
            return {"success": False, "error": "Operation validation failed", "validation": validation}
        
        # Status callback for progress updates
        def status_callback(message: str):
            logger.info(f"Replay Status: {message}")
        
        # Perform replay
        result = replay_session(operations, status_callback)
        
        if result["success"]:
            logger.info("Replay completed successfully")
        else:
            logger.error(f"Replay failed: {result.get('error', 'Unknown error')}")
        
        return result
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information and status.
        
        Returns:
            Dictionary with system information
        """
        capture_path = self.config.get_capture_path()
        
        info = {
            "tshark_available": check_tshark_availability(),
            "capture_path": capture_path,
            "capture_valid": validate_pcap_file(capture_path) if capture_path else False,
            "supported_commands": get_supported_commands(),
            "traces_folder": self.config.traces_folder,
            "verbosity_level": self.config.pcap_config.get("verbose_level", 0)
        }
        
        if capture_path and info["capture_valid"]:
            info["packet_count"] = get_packet_count(capture_path)
        
        return info
    
    def set_verbosity(self, level: int):
        """Set system verbosity level.
        
        Args:
            level: Verbosity level (0-3)
        """
        set_verbosity(level)
        logger.info(f"Set verbosity level to {level}")
    
    def configure_replay(self, server_ip: Optional[str] = None, 
                        domain: Optional[str] = None, username: Optional[str] = None,
                        password: Optional[str] = None, tree_name: Optional[str] = None,
                        max_wait: Optional[float] = None):
        """Configure replay server settings.
        
        Args:
            server_ip: SMB server IP address
            domain: SMB domain
            username: SMB username
            password: SMB password
            tree_name: SMB tree/share name
            max_wait: Maximum wait time for connections
        """
        config_updates = {}
        
        if server_ip is not None:
            config_updates["server_ip"] = server_ip
        if domain is not None:
            config_updates["domain"] = domain
        if username is not None:
            config_updates["username"] = username
        if password is not None:
            config_updates["password"] = password
        if tree_name is not None:
            config_updates["tree_name"] = tree_name
        if max_wait is not None:
            config_updates["max_wait"] = max_wait
        
        if config_updates:
            self.config.update_replay_config(**config_updates)
            logger.info(f"Updated replay configuration: {list(config_updates.keys())}")


def create_cli_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="SMB2 Replay System - Capture, analyze, and replay SMB2 traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available session IDs
  smbreplay list sessions --case 002 --trace trace001.pcapng

  # List available trace files (searches in configured case folder if case_id is set)
  smbreplay list traces

  # Configure case and then list traces
  smbreplay config set case_id 002
  smbreplay list traces

  # Display session information using session ID
  smbreplay session 0x00012c01c400000d --case 002 --trace trace001.pcapng

  # Using case+trace format
  smbreplay session case002+trace001

  # Using --case and --trace options
  smbreplay session --case 002 --trace trace001.pcapng

  # Using --trace with absolute path
  smbreplay session --trace /path/to/trace.pcapng

  # Using --trace with relative path (from current directory)
  smbreplay session --trace ./traces/trace001.pcapng

Note: The --trace option is used to specify the packet trace file (.pcap, .pcapng, .trc, .trc0) for analysis. 
      It can be combined with --case for organized case management, or used standalone
      with absolute or relative paths.
        """
    )
    
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity (can be used multiple times)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Global options for commands that need them
    def add_common_args(parser):
        parser.add_argument("--case", help="Case number/name (uses traces folder)")
        parser.add_argument("--trace", help="Trace file path (can be used with --case or as absolute/relative path)")
    
    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest PCAP file")
    ingest_parser.add_argument("pcap_file", nargs="?", help="Path to PCAP file")
    ingest_parser.add_argument("--force", action="store_true", help="Force re-ingestion")
    ingest_parser.add_argument("--reassembly", action="store_true", help="Enable TCP reassembly")
    add_common_args(ingest_parser)
    
    # List sessions command
    list_parser = subparsers.add_parser("list", help="List available sessions")
    list_subparsers = list_parser.add_subparsers(dest="list_action", help="List actions")
    
    # List sessions subcommand
    list_sessions_parser = list_subparsers.add_parser("sessions", help="List session IDs")
    list_sessions_parser.add_argument("--pcap", help="Path to PCAP file")
    add_common_args(list_sessions_parser)
    
    # List traces subcommand
    list_traces_parser = list_subparsers.add_parser("traces", help="List available trace files")
    add_common_args(list_traces_parser)
    
    # Session command
    session_parser = subparsers.add_parser("session", help="Display session information")
    session_parser.add_argument("session_file", nargs="?", help="Session file name or session ID")
    session_parser.add_argument("--pcap", help="Path to PCAP file")
    session_parser.add_argument("--file-filter", help="Filter by specific file")
    session_parser.add_argument("--fields", nargs="+", help="Fields to include")
    session_parser.add_argument("--session-id", help="Session ID to display (alternative to session_file)")
    session_parser.add_argument("--brief", action="store_true", help="Show brief output (one line per frame)")
    add_common_args(session_parser)
    
    # Replay command
    replay_parser = subparsers.add_parser("replay", help="Replay operations")
    replay_parser.add_argument("session_file", nargs="?", help="Session file name or session ID")
    replay_parser.add_argument("--session-id", help="Session ID to replay")
    replay_parser.add_argument("--pcap", help="Path to PCAP file")
    replay_parser.add_argument("--file-filter", help="Filter by specific file")
    replay_parser.add_argument("--server-ip", help="SMB server IP")
    replay_parser.add_argument("--domain", help="SMB domain")
    replay_parser.add_argument("--username", help="SMB username")
    replay_parser.add_argument("--password", help="SMB password")
    replay_parser.add_argument("--tree-name", help="SMB tree/share name")
    add_common_args(replay_parser)
    
    # Config command
    config_parser = subparsers.add_parser("config", help="Configure system settings")
    config_subparsers = config_parser.add_subparsers(dest="config_action", help="Configuration actions")
    
    # Config show
    config_show_parser = config_subparsers.add_parser("show", help="Show current configuration")
    config_show_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    
    # Config set
    config_set_parser = config_subparsers.add_parser("set", help="Set configuration values")
    config_set_parser.add_argument("key", help="Configuration key (session_id, case_id, trace_name, etc.)")
    config_set_parser.add_argument("value", help="Configuration value")
    
    # Config get
    config_get_parser = config_subparsers.add_parser("get", help="Get configuration value")
    config_get_parser.add_argument("key", help="Configuration key")
    
    # Info command (simplified for system status)
    info_parser = subparsers.add_parser("info", help="Show system information")
    
    return parser


def resolve_pcap_path(args, config) -> Optional[str]:
    """Resolve PCAP file path from arguments and configuration.
    
    Args:
        args: Parsed command line arguments
        config: Configuration manager
        
    Returns:
        Resolved absolute path to PCAP file or None
    """
    # Direct pcap_file argument (highest priority)
    if hasattr(args, 'pcap_file') and args.pcap_file:
        return os.path.abspath(args.pcap_file)
    
    # --pcap argument (full path override)
    if hasattr(args, 'pcap') and args.pcap:
        return os.path.abspath(args.pcap)
    
    # --case + --trace combination
    if hasattr(args, 'case') and args.case and hasattr(args, 'trace') and args.trace:
        traces_folder = config.get_traces_folder()
        case_path = os.path.join(traces_folder, args.case)
        trace_path = os.path.join(case_path, args.trace)
        
        # Handle escaped spaces and normalize path
        trace_path = trace_path.replace("\\ ", " ")
        trace_path = os.path.normpath(trace_path)
        
        if os.path.exists(trace_path):
            return os.path.abspath(trace_path)
        else:
            logger.error(f"Trace file not found: {trace_path}")
            return None
    
    # --trace only
    if hasattr(args, 'trace') and args.trace:
        trace_path = args.trace.replace("\\ ", " ")
        
        # If --trace is an absolute path, allow it (full path override)
        if os.path.isabs(trace_path):
            return os.path.abspath(trace_path)
        
        # If --trace is relative, require case_id to be configured
        case_id = config.get_case_id()
        if not case_id:
            logger.error("Case ID must be configured when using relative --trace paths. Use 'smbreplay config set case_id <case_id>' or provide absolute path with --trace.")
            return None
        
        # Build path using configured case_id
        traces_folder = config.get_traces_folder()
        case_path = os.path.join(traces_folder, case_id)
        trace_path = os.path.join(case_path, trace_path)
        trace_path = os.path.normpath(trace_path)
        
        if os.path.exists(trace_path):
            return os.path.abspath(trace_path)
        else:
            logger.error(f"Trace file not found: {trace_path}")
            return None
    
    # Fall back to configured capture path - but require case_id
    case_id = config.get_case_id()
    if not case_id:
        logger.error("Case ID must be configured. Use 'smbreplay config set case_id <case_id>' or provide full path with --trace.")
        return None
    
    return config.get_capture_path()


def handle_config_command(args, config):
    """Handle configuration commands."""
    if not args.config_action:
        # Default to show if no action specified
        args.config_action = "show"
    
    if args.config_action == "show":
        capture_path = config.get_capture_path()
        trace_name = config.get_trace_name()
        
        # If trace name is not configured but capture path is available, derive it
        if not trace_name and capture_path:
            trace_name = os.path.basename(capture_path)
        
        info = {
            "traces_folder": config.get_traces_folder(),
            "capture_path": capture_path,
            "verbosity_level": config.get_verbosity_level(),
            "session_id": config.get_session_id(),
            "case_id": config.get_case_id(),
            "trace_name": trace_name,
            "tshark_available": check_tshark_availability(),
            "supported_commands": get_supported_commands(),
            "server_ip": config.get_server_ip(),
            "domain": config.get_domain(),
            "username": config.get_username(),
            "password": "***" if config.get_password() != "PASSWORD" else config.get_password(),
            "tree_name": config.get_tree_name(),
            "max_wait": config.get_max_wait()
        }
        
        # Handle format attribute - it might not exist if we defaulted to show
        format_type = getattr(args, 'format', 'table')
        
        if format_type == "json":
            import json
            print(json.dumps(info, indent=2))
        else:
            print("Current Configuration:")
            print(f"  Traces folder: {info['traces_folder']}")
            print(f"  Capture path: {info['capture_path'] or 'Not configured'}")
            print(f"  Verbosity level: {info['verbosity_level']}")
            print(f"  Session ID: {info['session_id'] or 'Not configured'}")
            print(f"  Case ID: {info['case_id'] or 'Not configured'}")
            print(f"  Trace name: {info['trace_name'] or 'Not configured'}")
            print(f"  TShark available: {info['tshark_available']}")
            print(f"  Supported commands: {', '.join(info['supported_commands'].values())}")
            print(f"  Server IP: {info['server_ip']}")
            print(f"  Domain: {info['domain']}")
            print(f"  Username: {info['username']}")
            print(f"  Password: {info['password']}")
            print(f"  Tree name: {info['tree_name']}")
            print(f"  Max wait: {info['max_wait']}")
    
    elif args.config_action == "set":
        if args.key == "traces_folder":
            config.set_traces_folder(args.value)
            print(f"Set traces_folder to: {args.value}")
        elif args.key == "capture_path":
            config.set_capture_path(args.value)
            print(f"Set capture_path to: {args.value}")
        elif args.key == "verbosity_level":
            try:
                level = int(args.value)
                set_verbosity(level)
                print(f"Set verbosity_level to: {level}")
            except ValueError:
                print(f"Error: verbosity_level must be a number")
        elif args.key == "session_id":
            config.set_session_id(args.value)
            print(f"Set session_id to: {args.value}")
        elif args.key == "case_id":
            config.set_case_id(args.value)
            print(f"Set case_id to: {args.value}")
        elif args.key == "trace_name":
            config.set_trace_name(args.value)
            print(f"Set trace_name to: {args.value}")
        elif args.key == "server_ip":
            config.set_server_ip(args.value)
            print(f"Set server_ip to: {args.value}")
        elif args.key == "domain":
            config.set_domain(args.value)
            print(f"Set domain to: {args.value}")
        elif args.key == "username":
            config.set_username(args.value)
            print(f"Set username to: {args.value}")
        elif args.key == "password":
            config.set_password(args.value)
            print(f"Set password to: {args.value}")
        elif args.key == "tree_name":
            config.set_tree_name(args.value)
            print(f"Set tree_name to: {args.value}")
        elif args.key == "max_wait":
            try:
                max_wait = float(args.value)
                config.set_max_wait(max_wait)
                print(f"Set max_wait to: {max_wait}")
            except ValueError:
                print(f"Error: max_wait must be a number")
        else:
            print(f"Error: Unknown configuration key: {args.key}")
            print("Available keys: traces_folder, capture_path, verbosity_level, session_id, case_id, trace_name, server_ip, domain, username, password, tree_name, max_wait")
    
    elif args.config_action == "get":
        if args.key == "traces_folder":
            print(config.get_traces_folder())
        elif args.key == "capture_path":
            print(config.get_capture_path() or "")
        elif args.key == "verbosity_level":
            print(config.get_verbosity_level())
        elif args.key == "session_id":
            print(config.get_session_id() or "")
        elif args.key == "case_id":
            print(config.get_case_id() or "")
        elif args.key == "trace_name":
            print(config.get_trace_name() or "")
        elif args.key == "server_ip":
            print(config.get_server_ip())
        elif args.key == "domain":
            print(config.get_domain())
        elif args.key == "username":
            print(config.get_username())
        elif args.key == "password":
            print(config.get_password())
        elif args.key == "tree_name":
            print(config.get_tree_name())
        elif args.key == "max_wait":
            print(config.get_max_wait())
        else:
            print(f"Error: Unknown configuration key: {args.key}")
            print("Available keys: traces_folder, capture_path, verbosity_level, session_id, case_id, trace_name, server_ip, domain, username, password, tree_name, max_wait")


def main():
    """Main entry point for command-line interface."""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    # Create system instance
    system = SMB2ReplaySystem()
    
    # Set verbosity
    if args.verbose:
        system.set_verbosity(min(args.verbose, 3))
    
    # Set up system
    if not system.setup_system():
        logger.error("System setup failed")
        sys.exit(1)
    
    # Handle commands
    if args.command == "ingest":
        pcap_path = resolve_pcap_path(args, system.config)
        if not pcap_path:
            print("Error: No PCAP file specified. Use --help for usage.")
            sys.exit(1)
        
        result = system.ingest_pcap(
            pcap_path,
            force_reingest=args.force,
            reassembly=args.reassembly,
            verbose=args.verbose > 0
        )
        if result:
            print(f"Ingestion completed: {len(result['sessions'])} sessions extracted")
        else:
            print("Ingestion failed")
            sys.exit(1)
    
    elif args.command == "list":
        if not args.list_action:
            print("List commands: sessions, traces")
            return
        
        if args.list_action == "sessions":
            pcap_path = resolve_pcap_path(args, system.config)
            sessions = system.list_sessions(pcap_path)
            if sessions:
                print(f"Available sessions ({len(sessions)}):")
                for session in sessions:
                    # Extract session ID from filename
                    if session.startswith("smb2_session_") and session.endswith(".parquet"):
                        session_id = session.replace("smb2_session_", "").replace(".parquet", "")
                        print(f"  - {session_id}")
                    else:
                        print(f"  - {session}")
            else:
                print("No sessions found")
        
        elif args.list_action == "traces":
            traces = system.list_traces()
            case_id = system.config.get_case_id()
            
            if not case_id:
                print("Error: Case ID must be configured to list traces.")
                print("Use: smbreplay config set case_id <case_id>")
                return
            
            traces_folder = system.config.get_traces_folder()
            
            if traces:
                search_location = f"{traces_folder}/{case_id}/"
                print(f"Available trace files in case {case_id} ({len(traces)}):")
                
                for trace in traces:
                    print(f"  - {trace}")
            else:
                search_location = f"{traces_folder}/{case_id}/"
                print(f"No trace files found in case {case_id} folder: {search_location}")
    
    elif args.command == "session":
        # Handle session ID resolution
        session_file = args.session_file
        session_id = args.session_id

        # If session_file is provided and does not end with .parquet, treat as session ID and construct proper filename
        if session_file and not session_file.endswith('.parquet'):
            session_id = session_file  # Store the original session ID
            session_file = f"smb2_session_{session_file}.parquet"

        # If --session-id is provided, override session_file
        if session_id and session_id != session_file:
            session_file = f"smb2_session_{session_id}.parquet"

        if not session_file:
            print("Error: No session file or session ID provided")
            sys.exit(1)

        # Update configuration with session information
        if session_id:
            system.config.set_session_id(session_id)
        
        # Update case ID if provided
        if hasattr(args, 'case') and args.case:
            system.config.set_case_id(args.case)
        
        # Update trace name if provided
        if hasattr(args, 'trace') and args.trace:
            system.config.set_trace_name(args.trace)

        pcap_path = resolve_pcap_path(args, system.config)
        print(f"Loading session: {session_file}")

        operations = system.get_session_info(
            session_file,
            capture_path=pcap_path,
            file_filter=args.file_filter,
            fields=args.fields
        )

        if operations:
            print(f"\nSession information: {len(operations)} operations found")
            print("=" * 80)

            if args.brief:
                # Brief output - one line per frame
                print(f"{'#':<3} {'Frame':<6} {'Command':<25} {'Status':<20} {'Tree':<12} {'Path'}")
                print("-" * 80)
                
                for i, op in enumerate(operations, 1):
                    frame = op.get('Frame', 'N/A')
                    command = op.get('Command', 'Unknown')
                    path = op.get('Path', 'N/A')
                    status = op.get('Status', 'N/A')
                    tree = op.get('Tree', 'N/A')

                    # Truncate long paths for brief display
                    if path != 'N/A' and len(path) > 50:
                        path = "..." + path[-47:]
                    
                    # Truncate long status messages
                    if status != 'N/A' and len(status) > 18:
                        status = status[:15] + "..."
                    
                    # Truncate long tree names
                    if tree != 'N/A' and len(tree) > 10:
                        tree = tree[:7] + "..."

                    print(f"{i:<3} {frame:<6} {command:<25} {status:<20} {tree:<12} {path}")
            else:
                # Detailed output - multiple lines per operation
                for i, op in enumerate(operations, 1):
                    frame = op.get('Frame', 'N/A')
                    command = op.get('Command', 'Unknown')
                    path = op.get('Path', 'N/A')
                    status = op.get('Status', 'N/A')
                    tree = op.get('Tree', 'N/A')

                    # Extract filename from path if it's not N/A
                    if path != 'N/A' and '\\' in path:
                        filename = path.split('\\')[-1]
                        if filename:
                            display_path = f"{path} ({filename})"
                        else:
                            display_path = path
                    else:
                        display_path = path

                    print(f"{i:3d}. Frame {frame:>6} | {command:<25} | {display_path}")
                    print(f"     Status: {status} | Tree: {tree}")

                    # Show additional fields if present
                    extra_fields = []
                    for key, value in op.items():
                        if key not in ['Frame', 'Command', 'Path', 'Status', 'StatusDesc', 'Tree', 'orig_idx']:
                            if value and str(value).strip() != 'N/A' and str(value).strip() != '':
                                extra_fields.append(f"{key}: {value}")

                    if extra_fields:
                        print(f"     Additional: {' | '.join(extra_fields)}")

                    print()  # Empty line between operations

        else:
            print("Session analysis failed")
            sys.exit(1)
    
    elif args.command == "replay":
        # Handle session ID resolution (same logic as session command)
        session_file = args.session_file
        session_id = args.session_id

        # If session_file is provided and does not end with .parquet, treat as session ID and construct proper filename
        if session_file and not session_file.endswith('.parquet'):
            session_id = session_file  # Store the original session ID
            session_file = f"smb2_session_{session_file}.parquet"

        # If --session-id is provided, override session_file
        if session_id and session_id != session_file:
            session_file = f"smb2_session_{session_id}.parquet"

        # If no session specified, try to use configured session
        if not session_file and not session_id:
            session_id = system.config.get_session_id()
            if session_id:
                session_file = f"smb2_session_{session_id}.parquet"
                print(f"Using configured session: {session_id}")
            else:
                print("Error: No session specified and no session configured")
                print("Use: smbreplay replay <session_id> or configure a session with 'smbreplay config set session_id <session_id>'")
                sys.exit(1)

        # Update configuration with session information
        if session_id:
            system.config.set_session_id(session_id)
        
        # Update case ID if provided
        if hasattr(args, 'case') and args.case:
            system.config.set_case_id(args.case)
        
        # Update trace name if provided
        if hasattr(args, 'trace') and args.trace:
            system.config.set_trace_name(args.trace)

        # Configure replay if provided
        system.configure_replay(
            server_ip=args.server_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
            tree_name=args.tree_name
        )
        
        # Get session info first
        pcap_path = resolve_pcap_path(args, system.config)
        print(f"Loading session for replay: {session_file}")
        
        operations = system.get_session_info(
            session_file,
            capture_path=pcap_path,
            file_filter=args.file_filter
        )
        
        if not operations:
            print("Failed to get session info for replay")
            sys.exit(1)
        
        print(f"Loaded {len(operations)} operations for replay")
        
        # Replay operations
        result = system.replay_operations(operations)
        if result["success"]:
            print(f"Replay completed successfully: {result['successful_operations']}/{result['total_operations']} operations")
        else:
            print(f"Replay failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    
    elif args.command == "config":
        handle_config_command(args, system.config)
    
    elif args.command == "info":
        info = system.get_system_info()
        print("SMB2 Replay System Status:")
        print(f"  Version: 1.0.0")
        print(f"  TShark available: {info['tshark_available']}")
        print(f"  Supported commands: {', '.join(info['supported_commands'].values())}")
        
        # Show current active configuration
        current_pcap = info.get('capture_path')
        if current_pcap:
            print(f"  Current PCAP: {current_pcap}")
            if info.get('packet_count'):
                print(f"  Packet count: {info['packet_count']}")
        else:
            print("  No PCAP currently loaded")
    
    elif args.command is None:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main() 