"""
Main entry point for SMB2 Replay System.
Orchestrates all components and provides a command-line interface.
"""

import argparse
import contextlib
import logging
import os
import signal
import sys
from typing import Any

# Only import lightweight modules at startup
# Import config directly to avoid loading the entire package
import smbreplay.config

get_config = smbreplay.config.get_config
get_logger = smbreplay.config.get_logger
set_verbosity = smbreplay.config.set_verbosity

logger: logging.Logger | None = None


def _get_logger():
    """Get logger with lazy initialization."""
    global logger
    if logger is None:
        logger = get_logger()
    return logger


# Lazy import functions for heavy dependencies
def _check_tshark_availability():
    from .constants import check_tshark_availability

    return check_tshark_availability()


def _get_session_manager():
    from .session_manager import get_session_manager

    return get_session_manager()


def _get_supported_commands():
    from .replay import get_supported_commands

    return get_supported_commands()


def _validate_pcap_file(path):
    from .tshark_processor import validate_pcap_file

    return validate_pcap_file(path)


def _get_packet_count(path):
    from .tshark_processor import get_packet_count

    return get_packet_count(path)


def _run_ingestion(**kwargs):
    from .ingestion import run_ingestion

    return run_ingestion(**kwargs)


def _validate_ingested_data(data):
    from .ingestion import validate_ingested_data

    return validate_ingested_data(data)


def _replay_session(operations, callback):
    from .replay import replay_session

    return replay_session(operations, callback)


def _validate_operations(operations):
    from .replay import validate_operations

    return validate_operations(operations)


def handle_broken_pipe():
    """Handle broken pipe errors gracefully."""
    # Set up signal handler for SIGPIPE to default behavior
    # This prevents Python from raising BrokenPipeError for SIGPIPE
    # SIGPIPE is not available on Windows, so we need to check for it
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def safe_print(*args, **kwargs):
    """Print function that handles broken pipe errors gracefully."""
    try:
        print(*args, **kwargs)
        # Don't flush after every print - let Python handle buffering
    except BrokenPipeError:
        # Handle broken pipe by exiting quietly
        # This is the expected behavior when piping to head, less, etc.
        sys.exit(0)  # Exit with success code, not error
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        sys.exit(1)


class SMB2ReplaySystem:
    """Main orchestrator for the SMB2 replay system."""

    def __init__(self):
        self.config = get_config()
        self._session_manager = None  # Lazy initialization

    @property
    def session_manager(self):
        """Lazy-loaded session manager."""
        if self._session_manager is None:
            self._session_manager = _get_session_manager()
        return self._session_manager

    def setup_system(self) -> bool:
        """Set up and validate the system environment.

        Returns:
            True if setup successful, False otherwise
        """
        _get_logger().info("Setting up SMB2 replay system")

        # Only check tshark for commands that actually need it
        # For config commands, we can skip this check to improve performance

        _get_logger().info("System setup completed successfully")
        return True

    def setup_system_full(self) -> bool:
        """Set up and validate the system environment with full checks.

        Returns:
            True if setup successful, False otherwise
        """
        _get_logger().info("Setting up SMB2 replay system")

        # Check tshark availability
        if not _check_tshark_availability():
            _get_logger().critical(
                "tshark is not available. Please install Wireshark/tshark"
            )
            return False

        _get_logger().info("System setup completed successfully")
        return True

    def ingest_pcap(
        self,
        pcap_path: str,
        force_reingest: bool = False,
        reassembly: bool = False,
        verbose: bool = False,
    ) -> dict[str, Any] | None:
        """Ingest a PCAP file for analysis.

        Args:
            pcap_path: Path to PCAP file
            force_reingest: Force re-ingestion even if data exists
            reassembly: Enable TCP reassembly
            verbose: Enable verbose logging

        Returns:
            Dictionary with ingestion results or None if failed
        """
        _get_logger().info(f"Ingesting PCAP file: {pcap_path}")

        # Validate PCAP file
        if not _validate_pcap_file(pcap_path):
            _get_logger().error(f"Invalid PCAP file: {pcap_path}")
            return None

        # Set capture path in config
        self.config.set_capture_path(pcap_path)

        # Status callback for progress updates
        def status_callback(message: str):
            _get_logger().info(f"Ingestion Status: {message}")

        # Run ingestion
        result = _run_ingestion(
            capture_path=pcap_path,
            reassembly_enabled=reassembly,
            force_reingest=force_reingest,
            verbose=verbose,
            status_callback=status_callback,
        )

        if result and _validate_ingested_data(result):
            _get_logger().info("PCAP ingestion completed successfully")
            return result
        else:
            _get_logger().error("PCAP ingestion failed")
            return None

    def list_sessions(self, capture_path: str | None = None) -> list[str]:
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
            _get_logger().error("No capture path configured")
            return []

        output_dir = self.session_manager.get_output_directory(capture_path)
        if not output_dir:
            _get_logger().error("Could not determine output directory")
            return []

        return self.session_manager.list_session_files(output_dir)

    def list_traces(self, case_id: str | None = None) -> list[str]:
        """List available trace files in the traces folder.

        Args:
            case_id: Optional case ID to override configured case_id

        Returns:
            List of validated trace file names (PCAP files)
        """
        traces_folder = self.config.get_traces_folder()

        # Use provided case_id or fall back to configured case_id
        if case_id is None:
            case_id = self.config.get_case_id()

        # Require case_id to be configured for list traces
        if not case_id:
            _get_logger().error(
                "Case ID must be configured to list traces. Use 'smbreplay config set case_id <case_id>' or provide --case argument"
            )
            return []

        # If case_id is configured, look in traces_folder/case_id/
        search_folder = os.path.join(traces_folder, case_id)

        if not os.path.exists(search_folder):
            _get_logger().warning(f"Case folder does not exist: {search_folder}")
            return []

        trace_files = []
        try:
            for root, dirs, files in os.walk(search_folder):
                for file in files:
                    if file.lower().endswith((".pcap", ".pcapng", ".trc", ".trc0")):
                        # Get full path for validation
                        full_path = os.path.join(root, file)

                        # Validate the PCAP file using tshark
                        if _validate_pcap_file(full_path):
                            # Get relative path from search folder
                            relative_path = os.path.relpath(full_path, search_folder)
                            trace_files.append(relative_path)
                        else:
                            _get_logger().debug(
                                f"Skipping invalid PCAP file: {full_path}"
                            )
        except Exception as e:
            _get_logger().error(f"Error listing traces: {e}")
            return []

        return sorted(trace_files)

    def get_session_info(
        self,
        session_file: str,
        capture_path: str | None = None,
        file_filter: str | None = None,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]] | None:
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
            _get_logger().error("No capture path configured")
            return None

        _get_logger().info(f"Analyzing session: {session_file}")

        # Load session data
        session_frames, field_options, file_options, selected_fields = (
            self.session_manager.load_and_summarize_session(capture_path, session_file)
        )

        if session_frames is None:
            _get_logger().error(f"Failed to load session: {session_file}")
            return None

        # Use provided fields or defaults
        if fields:
            selected_fields = [f for f in fields if f in field_options]

        # Update operations
        operations = self.session_manager.update_operations(
            capture_path, session_file, file_filter, selected_fields
        )

        _get_logger().info(
            f"Analyzed session {session_file}: {len(operations)} operations"
        )
        return operations

    def replay_operations(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        """Replay a list of operations.

        Args:
            operations: List of operation dictionaries

        Returns:
            Dictionary with replay results
        """
        _get_logger().info(f"Replaying {len(operations)} operations")

        # Validate operations
        validation = _validate_operations(operations)
        if not validation["valid"]:
            _get_logger().error(f"Operation validation failed: {validation['issues']}")
            return {
                "success": False,
                "error": "Operation validation failed",
                "validation": validation,
            }

        # Status callback for progress updates
        def status_callback(message: str):
            _get_logger().info(f"Replay Status: {message}")

        # Perform replay
        result = _replay_session(operations, status_callback)

        if result["success"]:
            _get_logger().info("Replay completed successfully")
        else:
            _get_logger().error(
                f"Replay failed: {result.get('error', 'Unknown error')}"
            )

        return result

    def validate_replay_readiness(
        self,
        operations: list[dict[str, Any]],
        check_fs: bool = True,
        check_ops: bool = True,
    ) -> dict[str, Any]:
        """
        Validate that the system is ready for replay.

        Args:
            operations: List of operations to validate
            check_fs: Whether to check file system structure
            check_ops: Whether to check operation validity

        Returns:
            Dictionary with validation results
        """
        results: dict[str, Any] = {
            "ready": True,
            "checks": {},
            "errors": [],
            "warnings": [],
        }

        # Check operation validity
        if check_ops:
            safe_print("Validating operations...")
            op_validation = _validate_operations(operations)
            results["checks"]["operations"] = op_validation

            if not op_validation.get("valid", False):
                results["ready"] = False
                results["errors"].append("Operation validation failed")
                for issue in op_validation.get("issues", []):
                    results["errors"].append(f"  - {issue}")

        # Check file system structure
        if check_fs and operations:
            safe_print("Checking file system structure...")
            fs_validation = self._validate_file_system_structure(operations)
            results["checks"]["file_system"] = fs_validation

            if not fs_validation.get("ready", False):
                results["ready"] = False
                results["errors"].append("File system structure not ready")
                for missing in fs_validation.get("missing_directories", []):
                    results["errors"].append(f"  - Missing directory: {missing}")

            for warning in fs_validation.get("warnings", []):
                results["warnings"].append(warning)

        return results

    def _validate_file_system_structure(
        self, operations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Validate file system structure without connecting to SMB server.

        Args:
            operations: List of operations to analyze

        Returns:
            Dictionary with validation results
        """
        all_paths = set()
        created_files = set()
        existing_files = set()

        # Collect all valid paths and created files
        for op in operations:
            filename = op.get("smb2.filename", "")
            if filename and filename not in [".", "..", "N/A", ""]:
                # Strip leading slashes to normalize paths like "\file96.txt"
                all_paths.add(filename.lstrip("\\/"))
            if (
                op.get("smb2.cmd") == "5"
                and op.get("smb2.flags.response") == "True"
                and op.get("smb2.create.action") == "FILE_CREATED"
            ):
                created_files.add(filename.lstrip("\\/"))
            elif (
                op.get("smb2.cmd") == "5"
                and op.get("smb2.flags.response") == "True"
                and op.get("smb2.create.action") == "FILE_OPENED"
            ):
                existing_files.add(filename.lstrip("\\/"))

        if not all_paths:
            return {
                "ready": True,
                "message": "No file paths to validate",
                "missing_directories": [],
                "warnings": [],
            }

        # Normalize paths and extract directories
        directories = set()
        normalized_paths = set()

        for path in all_paths:
            # Normalize path separators (handle both \ and /)
            normalized_path = path.replace("/", "\\")
            normalized_paths.add(normalized_path)

            # Extract parent directories for all paths with multiple parts
            parts = normalized_path.split("\\")
            if len(parts) > 1:
                for i in range(1, len(parts)):
                    dir_path = "\\".join(parts[:i])
                    if dir_path:
                        directories.add(dir_path)

        # Check which directories will be needed
        missing_dirs = set()
        accessible_paths = 0

        for path in normalized_paths:
            # Check if the parent directory exists for each path
            parts = path.split("\\")
            if len(parts) > 1:
                parent_dir = "\\".join(parts[:-1])
                missing_dirs.add(
                    parent_dir
                )  # All directories will be missing initially
            else:
                # File in root directory
                accessible_paths += 1

        warnings = []
        if len(missing_dirs) > 0:
            warnings.append(f"Will need to create {len(missing_dirs)} directories")
            warnings.append("SMB server may not support nested directory creation")

        return {
            "ready": len(missing_dirs)
            == 0,  # Only ready if no nested directories needed
            "total_paths": len(normalized_paths),
            "accessible_paths": accessible_paths,
            "missing_directories": sorted(missing_dirs),
            "created_files": len(created_files),
            "existing_files": len(existing_files),
            "warnings": warnings,
        }

    def cleanup_existing_files(
        self, tree, paths: set, dry_run: bool = False
    ) -> dict[str, Any]:
        """
        Clean up existing files and directories that will be recreated during replay.

        Args:
            tree: TreeConnect object to the share
            paths: Set of all paths that will be accessed during replay
            dry_run: Show what would be deleted without making changes

        Returns:
            Dictionary with cleanup results
        """
        # Import here to avoid circular imports
        from smbprotocol.exceptions import SMBException
        from smbprotocol.open import Open

        results = {
            "success": True,
            "files_deleted": 0,
            "dirs_deleted": 0,
            "errors": [],
            "dry_run": dry_run,
        }

        if not paths:
            safe_print("ℹ️  No paths to clean up")
            return results

        # Normalize paths - strip leading slashes and convert to backslashes
        normalized_paths = {
            path.replace("/", "\\").lstrip("\\") for path in paths if path
        }

        # Sort paths by depth (deepest first) to delete files before directories
        sorted_paths = sorted(
            normalized_paths, key=lambda x: (x.count("\\"), x), reverse=True
        )

        if dry_run:
            safe_print(f"DRY RUN: Would clean up {len(sorted_paths)} paths:")
            for path in sorted_paths[:10]:  # Show first 10
                safe_print(f"  - {path}")
            if len(sorted_paths) > 10:
                safe_print(f"  ... and {len(sorted_paths) - 10} more")
            return results

        safe_print(f"Cleaning up {len(sorted_paths)} existing files/directories...")

        for path in sorted_paths:
            try:
                # Try to open and delete the path using FILE_DELETE_ON_CLOSE
                file_open = Open(tree, path)
                file_open.create(
                    impersonation_level=0,  # SECURITY_ANONYMOUS
                    desired_access=0x00010000,  # DELETE
                    file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=1,  # FILE_OPEN
                    create_options=0x00001000,  # FILE_DELETE_ON_CLOSE
                )

                # Close the file which will delete it due to FILE_DELETE_ON_CLOSE
                file_open.close()

                if isinstance(results["files_deleted"], int):
                    results["files_deleted"] += 1
                else:
                    results["files_deleted"] = 1
                safe_print(f"  ✓ Deleted: {path}")

            except SMBException as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    # File doesn't exist, which is fine
                    pass
                elif "STATUS_ACCESS_DENIED" in str(e):
                    # Access denied, might be a directory or protected file
                    if isinstance(results["errors"], list):
                        results["errors"].append(f"Access denied: {path}")
                    else:
                        results["errors"] = [f"Access denied: {path}"]
                else:
                    if isinstance(results["errors"], list):
                        results["errors"].append(f"Failed to delete {path}: {e}")
                    else:
                        results["errors"] = [f"Failed to delete {path}: {e}"]

        safe_print(f"✅ Cleanup completed: {results['files_deleted']} files deleted")
        if isinstance(results["errors"], list) and len(results["errors"]):
            safe_print(f"⚠️  {len(results['errors'])} errors during cleanup")
        elif results["errors"]:
            safe_print("⚠️  1 error during cleanup")

        return results

    def setup_file_system_infrastructure(
        self,
        operations: list[dict[str, Any]],
        dry_run: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Build file system infrastructure on SMB server for replay.
        First cleans up any existing files to ensure a clean replay.

        Args:
            operations: List of operations to analyze
            dry_run: Show what would be created without making changes
            force: Force creation even if directories exist

        Returns:
            Dictionary with setup results
        """
        results = {
            "success": True,
            "directories_created": 0,
            "files_created": 0,
            "errors": [],
            "warnings": [],
            "dry_run": dry_run,
        }

        # Get replay configuration
        replay_config = self.config.replay_config.copy()
        server_ip = replay_config.get("server_ip", "127.0.0.1")
        port = int(replay_config.get("port", 445))
        username = replay_config.get("username", "testuser")
        password = replay_config.get("password", "PASSWORD")
        tree_name = replay_config.get("tree_name", "testshare")

        if dry_run:
            safe_print(f"DRY RUN: Would connect to {server_ip}:{port} as {username}")
            safe_print(f"DRY RUN: Would use tree: {tree_name}")
        else:
            safe_print(f"Connecting to {server_ip} as {username}...")

        try:
            if not dry_run:
                # Import here to avoid circular imports
                import uuid

                from smbprotocol.connection import Connection
                from smbprotocol.exceptions import SMBException
                from smbprotocol.open import Open
                from smbprotocol.session import Session
                from smbprotocol.tree import TreeConnect

                # Setup connection
                connection = Connection(uuid.uuid4(), server_ip, port)
                connection.connect(timeout=5.0)
                session = Session(
                    connection, username, password, require_encryption=False
                )
                session.connect()
                tree = TreeConnect(session, f"\\\\{server_ip}\\{tree_name}")
                tree.connect()

                safe_print("✅ Connected to SMB server")
            else:
                connection = session = tree = None

            # Analyze operations to get required infrastructure
            all_paths = set()
            created_files = set()
            existing_files = set()

            for op in operations:
                filename = op.get("smb2.filename", "")
                if filename and filename not in [".", "..", "N/A", ""]:
                    # Strip leading slashes to normalize paths like "\file96.txt"
                    all_paths.add(filename.lstrip("\\/"))
                if (
                    op.get("smb2.cmd") == "5"
                    and op.get("smb2.flags.response") == "True"
                    and op.get("smb2.create.action") == "FILE_CREATED"
                ):
                    created_files.add(filename.lstrip("\\/"))
                elif (
                    op.get("smb2.cmd") == "5"
                    and op.get("smb2.flags.response") == "True"
                    and op.get("smb2.create.action") == "FILE_OPENED"
                ):
                    existing_files.add(filename.lstrip("\\/"))

            if not all_paths:
                safe_print("ℹ️  No file paths to setup")
                return results

            # Clean up existing files first to ensure clean replay
            if not dry_run and tree:
                cleanup_results = self.cleanup_existing_files(tree, all_paths, dry_run)
                if isinstance(results["errors"], list) and isinstance(
                    cleanup_results["errors"], list
                ):
                    results["errors"].extend(cleanup_results["errors"])
                elif isinstance(cleanup_results["errors"], list):
                    results["errors"] = cleanup_results["errors"]

            # Normalize paths and extract directories
            directories = set()
            normalized_paths = set()

            for path in all_paths:
                normalized_path = path.replace("/", "\\")
                normalized_paths.add(normalized_path)

                # Extract parent directories for paths with multiple parts
                parts = normalized_path.split("\\")
                if len(parts) > 1:
                    for i in range(1, len(parts)):
                        dir_path = "\\".join(parts[:i])
                        if dir_path:
                            directories.add(dir_path)

            # Remove any paths that are actually files (not directories)
            # If a path exists in both directories and normalized_paths, it's likely a file
            file_paths = normalized_paths - directories
            directories = directories - normalized_paths

            # Add directories needed for nested file paths
            for path in file_paths:
                parts = path.split("\\")
                if len(parts) > 1:
                    for i in range(1, len(parts)):
                        dir_path = "\\".join(parts[:i])
                        if dir_path and dir_path not in file_paths:
                            directories.add(dir_path)

            safe_print(f"📁 Found {len(directories)} directories to create")
            safe_print(f"📄 Found {len(normalized_paths)} files to process")

            # Create directories in proper order
            sorted_dirs = sorted(directories, key=lambda x: (x.count("\\"), x))
            created_dirs = set()

            for dir_path in sorted_dirs:
                parts = dir_path.split("\\")
                current_path = ""

                for i, part in enumerate(parts):
                    if i == 0:
                        current_path = part
                    else:
                        current_path = current_path + "\\" + part

                    if current_path in created_dirs:
                        continue

                    if dry_run:
                        safe_print(f"DRY RUN: Would create directory: {current_path}")
                        created_dirs.add(current_path)
                        if isinstance(results["directories_created"], int):
                            results["directories_created"] += 1
                        else:
                            results["directories_created"] = 1
                    else:
                        try:
                            dir_open = Open(tree, current_path)
                            dir_open.create(
                                impersonation_level=0,
                                desired_access=0x80000000,
                                file_attributes=0x00000010,
                                share_access=0x00000001,
                                create_disposition=3,  # FILE_OPEN_IF - works better for existing directories
                                create_options=1,  # FILE_DIRECTORY_FILE - correct value
                            )
                            created_dirs.add(current_path)
                            if isinstance(results["directories_created"], int):
                                results["directories_created"] += 1
                            else:
                                results["directories_created"] = 1
                            safe_print(f"✅ Created directory: {current_path}")
                            dir_open.close()
                        except SMBException as e:
                            if "STATUS_OBJECT_NAME_COLLISION" not in str(e):
                                error_msg = (
                                    f"Failed to create directory {current_path}: {e}"
                                )
                                safe_print(f"❌ {error_msg}")
                                if isinstance(results["errors"], list):
                                    results["errors"].append(error_msg)
                                else:
                                    results["errors"] = [error_msg]
                                if not force:
                                    break
                            else:
                                created_dirs.add(current_path)
                                safe_print(
                                    f"⚠️  Directory already exists: {current_path}"
                                )

            # Create pre-existing files
            for path in normalized_paths:
                if path not in directories and path not in created_files:
                    if dry_run:
                        safe_print(f"DRY RUN: Would create file: {path}")
                        if isinstance(results["files_created"], int):
                            results["files_created"] += 1
                        else:
                            results["files_created"] = 1
                    else:
                        try:
                            file_open = Open(tree, path)
                            file_open.create(
                                impersonation_level=0,
                                desired_access=0x80000000 | 0x40000000,
                                file_attributes=0,
                                share_access=0x00000001,
                                create_disposition=3,  # FILE_OPEN_IF - create if doesn't exist, open if exists
                                create_options=0,
                            )
                            if isinstance(results["files_created"], int):
                                results["files_created"] += 1
                            else:
                                results["files_created"] = 1
                            safe_print(f"✅ Created file: {path}")
                            file_open.close()
                        except SMBException as e:
                            error_msg = f"Failed to create file {path}: {e}"
                            safe_print(f"❌ {error_msg}")
                            if isinstance(results["errors"], list):
                                results["errors"].append(error_msg)
                            else:
                                results["errors"] = [error_msg]

            # Cleanup
            if not dry_run and connection:
                with contextlib.suppress(Exception):
                    tree.disconnect()
                with contextlib.suppress(Exception):
                    session.disconnect()
                with contextlib.suppress(Exception):
                    connection.disconnect()

            # Set success based on errors
            if isinstance(results["errors"], list):
                results["success"] = len(results["errors"]) == 0
            else:
                results["success"] = not bool(results["errors"])

            if dry_run:
                safe_print("\nDRY RUN SUMMARY:")
                safe_print(
                    f"  Directories that would be created: {results['directories_created']}"
                )
                safe_print(f"  Files that would be created: {results['files_created']}")
            else:
                safe_print("\nSETUP SUMMARY:")
                safe_print(f"  Directories created: {results['directories_created']}")
                safe_print(f"  Files created: {results['files_created']}")
                if isinstance(results["errors"], list) and len(results["errors"]):
                    safe_print(f"  Errors: {len(results['errors'])}")
                elif results["errors"]:
                    safe_print("  Errors: 1")
                if results["success"]:
                    safe_print("✅ Setup completed successfully")
                else:
                    safe_print("❌ Setup completed with errors")

            return results

        except Exception as e:
            error_msg = f"Setup failed: {e}"
            safe_print(f"❌ {error_msg}")
            if isinstance(results["errors"], list):
                results["errors"].append(error_msg)
            else:
                results["errors"] = [error_msg]
            results["success"] = False
            return results

    def get_system_info(self) -> dict[str, Any]:
        """Get system information and status.

        Returns:
            Dictionary with system information
        """
        capture_path = self.config.get_capture_path()

        info = {
            "tshark_available": _check_tshark_availability(),
            "capture_path": capture_path,
            "capture_valid": (
                _validate_pcap_file(capture_path) if capture_path else False
            ),
            "supported_commands": _get_supported_commands(),
            "traces_folder": self.config.traces_folder,
            "verbosity_level": self.config.pcap_config.get("verbose_level", 0),
        }

        if capture_path and info["capture_valid"]:
            info["packet_count"] = _get_packet_count(capture_path)

        return info

    def set_verbosity(self, level: int):
        """Set system verbosity level.

        Args:
            level: Verbosity level (0-3)
        """
        set_verbosity(level)
        _get_logger().info(f"Set verbosity level to {level}")

    def configure_replay(
        self,
        server_ip: str | None = None,
        domain: str | None = None,
        username: str | None = None,
        password: str | None = None,
        tree_name: str | None = None,
        max_wait: float | None = None,
    ):
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
            config_updates["max_wait"] = str(max_wait)

        if config_updates:
            self.config.update_replay_config(**config_updates)
            _get_logger().info(
                f"Updated replay configuration: {list(config_updates.keys())}"
            )


def create_cli_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="SMB2 Replay System - Capture, analyze, and replay SMB2 traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Step-by-Step Workflow:
  1. Check configuration: smbreplay config show
  2. List traces: smbreplay list traces --case 2010101010
  3. Ingest PCAP: smbreplay ingest --trace "capture.pcap"
  4. List sessions: smbreplay session --list
  5. Analyze session: smbreplay session <session_id> --brief
  6. Replay session: smbreplay replay <session_id>

Examples:
  # 1. Check your configuration (required before replay)
  smbreplay config show

  # 2. List available trace files in a case directory
  smbreplay list traces --case 2010101010

  # 3. Ingest a PCAP file (use quotes for spaces or special paths)
  smbreplay ingest --trace "My Capture File.pcap"
  smbreplay ingest --trace /path/to/different/directory/capture.pcap

  # 4. List all SMB sessions in the ingested PCAP
  smbreplay session --list

  # 5. Display session information (brief format recommended for large sessions)
  smbreplay session 0x7602000009fbdaa3 --brief

  # 6. Replay the session to your configured target server
  smbreplay replay 0x7602000009fbdaa3

Configuration:
  # Set target server details
  smbreplay config set server_ip 192.168.1.100
  smbreplay config set domain your-domain.local
  smbreplay config set username your-username
  smbreplay config set tree_name your-share-name

  # Set case management
  smbreplay config set case_id 2010101010
  smbreplay config set traces_folder ~/cases

Note: You must configure your target server before attempting replay operations.
      Use 'smbreplay config show' to verify your configuration.

Data Storage:
  Processed session data is stored in .tracer directories:
  ~/cases/<case_id>/.tracer/<pcap_name>/sessions/
  - smb2_session_0x*.parquet: Session data files
  - session_metadata.json: Session metadata
        """,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Global options for commands that need them
    def add_common_args(parser):
        parser.add_argument("--case", help="Case number/name (uses traces folder)")
        parser.add_argument(
            "--trace",
            help="Trace file path (can be used with --case or as absolute/relative path)",
        )
        parser.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=0,
            help="Increase verbosity (can be used multiple times)",
        )

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Process PCAP file to extract SMB2 sessions"
    )
    ingest_parser.add_argument("pcap_file", nargs="?", help="Path to PCAP file")
    ingest_parser.add_argument(
        "--force", action="store_true", help="Force re-ingestion"
    )
    ingest_parser.add_argument(
        "--reassembly", action="store_true", help="Enable TCP reassembly"
    )
    add_common_args(ingest_parser)

    # List sessions command
    list_parser = subparsers.add_parser("list", help="List available traces")
    list_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )
    list_subparsers = list_parser.add_subparsers(
        dest="list_action", help="List actions"
    )

    # List traces subcommand
    list_traces_parser = list_subparsers.add_parser(
        "traces", help="List available PCAP files in traces directory"
    )
    add_common_args(list_traces_parser)

    # Session command
    session_parser = subparsers.add_parser(
        "session", help="Display session information or list available sessions"
    )
    session_parser.add_argument(
        "session_file", nargs="?", help="Session file name or session ID"
    )
    session_parser.add_argument("--file-filter", help="Filter by specific file")
    session_parser.add_argument("--fields", nargs="+", help="Fields to include")
    session_parser.add_argument(
        "--session-id", help="Session ID to display (alternative to session_file)"
    )
    session_parser.add_argument(
        "--brief", action="store_true", help="Show brief output (one line per frame)"
    )
    session_parser.add_argument(
        "--list",
        action="store_true",
        help="List available sessions instead of displaying session info",
    )
    add_common_args(session_parser)

    # Replay command
    replay_parser = subparsers.add_parser(
        "replay", help="Replay SMB2 operations to target server"
    )
    replay_parser.add_argument(
        "session_file", nargs="?", help="Session file name or session ID"
    )
    replay_parser.add_argument("--session-id", help="Session ID to replay")
    replay_parser.add_argument("--file-filter", help="Filter by specific file")
    replay_parser.add_argument("--server-ip", help="SMB server IP")
    replay_parser.add_argument("--domain", help="SMB domain")
    replay_parser.add_argument("--username", help="SMB username")
    replay_parser.add_argument("--password", help="SMB password")
    replay_parser.add_argument("--tree-name", help="SMB tree/share name")
    replay_parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate replay readiness before proceeding",
    )
    replay_parser.add_argument(
        "--no-ping", action="store_true", help="Disable replay start ping"
    )
    add_common_args(replay_parser)

    # Setup command
    setup_parser = subparsers.add_parser(
        "setup", help="Build file system infrastructure for replay"
    )
    setup_parser.add_argument(
        "session_file", nargs="?", help="Session file name or session ID"
    )
    setup_parser.add_argument("--session-id", help="Session ID to setup")
    setup_parser.add_argument("--file-filter", help="Filter by specific file")
    setup_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without making changes",
    )
    setup_parser.add_argument(
        "--force", action="store_true", help="Force creation even if directories exist"
    )
    setup_parser.add_argument("--server-ip", help="SMB server IP")
    setup_parser.add_argument("--domain", help="SMB domain")
    setup_parser.add_argument("--username", help="SMB username")
    setup_parser.add_argument("--password", help="SMB password")
    setup_parser.add_argument("--tree-name", help="SMB tree/share name")
    add_common_args(setup_parser)

    # Validate command
    validate_parser = subparsers.add_parser(
        "validate", help="Validate pre-trace setup and replay readiness"
    )
    validate_parser.add_argument(
        "session_file", nargs="?", help="Session file name or session ID"
    )
    validate_parser.add_argument("--session-id", help="Session ID to validate")
    validate_parser.add_argument("--file-filter", help="Filter by specific file")
    validate_parser.add_argument(
        "--check-fs",
        action="store_true",
        help="Check file system structure on SMB server",
    )
    validate_parser.add_argument(
        "--check-ops", action="store_true", help="Check operation validity"
    )
    validate_parser.add_argument(
        "--check-all", action="store_true", help="Check all validations (default)"
    )
    validate_parser.add_argument("--server-ip", help="SMB server IP")
    validate_parser.add_argument("--domain", help="SMB domain")
    validate_parser.add_argument("--username", help="SMB username")
    validate_parser.add_argument("--password", help="SMB password")
    validate_parser.add_argument("--tree-name", help="SMB tree/share name")
    add_common_args(validate_parser)

    # Config command
    config_parser = subparsers.add_parser(
        "config", help="Configure system settings (required before replay)"
    )
    config_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )
    config_subparsers = config_parser.add_subparsers(
        dest="config_action", help="Configuration actions"
    )

    # Config show
    config_show_parser = config_subparsers.add_parser(
        "show", help="Show current configuration (check this first)"
    )
    config_show_parser.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )
    config_show_parser.add_argument(
        "--quick", action="store_true", help="Skip heavy operations like tshark check"
    )

    # Config set
    config_set_parser = config_subparsers.add_parser(
        "set", help="Set configuration values"
    )
    config_set_parser.add_argument(
        "key",
        help="Configuration key (server_ip, domain, username, tree_name, case_id, traces_folder)",
    )
    config_set_parser.add_argument("value", help="Configuration value")

    # Config get
    config_get_parser = config_subparsers.add_parser(
        "get", help="Get configuration value"
    )
    config_get_parser.add_argument("key", help="Configuration key")

    # Info command (simplified for system status)
    _info_parser = subparsers.add_parser(
        "info", help="Show system information and status"
    )

    return parser


def resolve_pcap_path(args, config) -> str | None:
    """Resolve PCAP file path from arguments and configuration.

    Args:
        args: Parsed command line arguments
        config: Configuration manager

    Returns:
        Resolved absolute path to PCAP file or None
    """
    # Direct pcap_file argument (highest priority)
    if hasattr(args, "pcap_file") and args.pcap_file:
        return os.path.abspath(args.pcap_file)

    # --case + --trace combination
    if hasattr(args, "case") and args.case and hasattr(args, "trace") and args.trace:
        traces_folder = config.get_traces_folder()
        case_path = os.path.join(traces_folder, args.case)
        trace_path = os.path.join(case_path, args.trace)

        # Handle escaped spaces and normalize path
        trace_path = trace_path.replace("\\ ", " ")
        trace_path = os.path.normpath(trace_path)

        if os.path.exists(trace_path):
            return os.path.abspath(trace_path)
        else:
            _get_logger().error(f"Trace file not found: {trace_path}")
            return None

    # --trace only
    if hasattr(args, "trace") and args.trace:
        trace_path = args.trace.replace("\\ ", " ")

        # If --trace is an absolute path, allow it (full path override)
        if os.path.isabs(trace_path):
            return os.path.abspath(trace_path)

        # If --trace is relative, require case_id to be configured
        case_id = config.get_case_id()
        if not case_id:
            _get_logger().error(
                "Case ID must be configured when using relative --trace paths. Use 'smbreplay config set case_id <case_id>' or provide absolute path with --trace."
            )
            return None

        # Build path using configured case_id
        traces_folder = config.get_traces_folder()
        case_path = os.path.join(traces_folder, case_id)
        trace_path = os.path.join(case_path, trace_path)
        trace_path = os.path.normpath(trace_path)

        if os.path.exists(trace_path):
            return os.path.abspath(trace_path)
        else:
            _get_logger().error(f"Trace file not found: {trace_path}")
            return None

    # Fall back to configured capture path - but require case_id
    case_id = config.get_case_id()
    if not case_id:
        _get_logger().error(
            "Case ID must be configured. Use 'smbreplay config set case_id <case_id>' or provide full path with --trace."
        )
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

        # Handle format attribute - it might not exist if we defaulted to show
        format_type = getattr(args, "format", "table")

        # For basic config display, we can skip heavy operations
        if format_type == "json":
            # Only show configuration without heavy operations
            info = {
                "traces_folder": config.get_traces_folder(),
                "capture_path": capture_path,
                "verbosity_level": config.get_verbosity_level(),
                "session_id": config.get_session_id(),
                "case_id": config.get_case_id(),
                "trace_name": trace_name,
                "server_ip": config.get_server_ip(),
                "port": config.get_port(),
                "domain": config.get_domain(),
                "username": config.get_username(),
                "password": (
                    "***"
                    if config.get_password() != "PASSWORD"
                    else config.get_password()
                ),
                "tree_name": config.get_tree_name(),
                "max_wait": config.get_max_wait(),
            }

            import json

            safe_print(json.dumps(info, indent=2))
        else:
            # For table format, display configuration only
            safe_print("Current Configuration:")
            safe_print(f"  Traces folder: {config.get_traces_folder()}")
            safe_print(f"  Capture path: {capture_path or 'Not configured'}")
            safe_print(f"  Verbosity level: {config.get_verbosity_level()}")
            safe_print(f"  Session ID: {config.get_session_id() or 'Not configured'}")
            safe_print(f"  Case ID: {config.get_case_id() or 'Not configured'}")
            safe_print(f"  Trace name: {trace_name or 'Not configured'}")
            safe_print(f"  Server IP: {config.get_server_ip()}")
            safe_print(f"  Port: {config.get_port()}")
            safe_print(f"  Domain: {config.get_domain()}")
            safe_print(f"  Username: {config.get_username()}")
            safe_print(
                f"  Password: {'***' if config.get_password() != 'PASSWORD' else config.get_password()}"
            )
            safe_print(f"  Tree name: {config.get_tree_name()}")
            safe_print(f"  Max wait: {config.get_max_wait()}")

    elif args.config_action == "set":
        if args.key == "traces_folder":
            config.set_traces_folder(args.value)
            safe_print(f"Set traces_folder to: {args.value}")
        elif args.key == "capture_path":
            config.set_capture_path(args.value)
            safe_print(f"Set capture_path to: {args.value}")
        elif args.key == "verbosity_level":
            try:
                level = int(args.value)
                set_verbosity(level)
                safe_print(f"Set verbosity_level to: {level}")
            except ValueError:
                safe_print("Error: verbosity_level must be a number")
        elif args.key == "session_id":
            config.set_session_id(args.value)
            safe_print(f"Set session_id to: {args.value}")
        elif args.key == "case_id":
            config.set_case_id(args.value)
            safe_print(f"Set case_id to: {args.value}")
        elif args.key == "trace_name":
            config.set_trace_name(args.value)
            safe_print(f"Set trace_name to: {args.value}")
        elif args.key == "server_ip":
            config.set_server_ip(args.value)
            safe_print(f"Set server_ip to: {args.value}")
        elif args.key == "port":
            try:
                port = int(args.value)
                config.set_port(port)
                safe_print(f"Set port to: {port}")
            except ValueError:
                safe_print("Error: port must be a number")
        elif args.key == "domain":
            config.set_domain(args.value)
            safe_print(f"Set domain to: {args.value}")
        elif args.key == "username":
            config.set_username(args.value)
            safe_print(f"Set username to: {args.value}")
        elif args.key == "password":
            config.set_password(args.value)
            safe_print(f"Set password to: {args.value}")
        elif args.key == "tree_name":
            config.set_tree_name(args.value)
            safe_print(f"Set tree_name to: {args.value}")
        elif args.key == "max_wait":
            try:
                max_wait = float(args.value)
                config.set_max_wait(max_wait)
                safe_print(f"Set max_wait to: {max_wait}")
            except ValueError:
                safe_print("Error: max_wait must be a number")
        else:
            safe_print(f"Error: Unknown configuration key: {args.key}")
            safe_print(
                "Available keys: traces_folder, capture_path, verbosity_level, session_id, case_id, trace_name, server_ip, domain, username, password, tree_name, max_wait"
            )

    elif args.config_action == "get":
        if args.key == "traces_folder":
            safe_print(config.get_traces_folder())
        elif args.key == "capture_path":
            safe_print(config.get_capture_path() or "")
        elif args.key == "verbosity_level":
            safe_print(config.get_verbosity_level())
        elif args.key == "session_id":
            safe_print(config.get_session_id() or "")
        elif args.key == "case_id":
            safe_print(config.get_case_id() or "")
        elif args.key == "trace_name":
            safe_print(config.get_trace_name() or "")
        elif args.key == "server_ip":
            safe_print(config.get_server_ip())
        elif args.key == "port":
            safe_print(config.get_port())
        elif args.key == "domain":
            safe_print(config.get_domain())
        elif args.key == "username":
            safe_print(config.get_username())
        elif args.key == "password":
            safe_print(config.get_password())
        elif args.key == "tree_name":
            safe_print(config.get_tree_name())
        elif args.key == "max_wait":
            safe_print(config.get_max_wait())
        else:
            safe_print(f"Error: Unknown configuration key: {args.key}")
            safe_print(
                "Available keys: traces_folder, capture_path, verbosity_level, session_id, case_id, trace_name, server_ip, domain, username, password, tree_name, max_wait"
            )


def main():
    """Main entry point for command-line interface."""
    # Set up broken pipe handling
    handle_broken_pipe()

    try:
        _main_impl()
    except BrokenPipeError:
        # Handle broken pipe gracefully - exit quietly
        # This is expected when piping to head, less, grep, etc.
        sys.exit(0)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        sys.exit(1)
    except Exception as e:
        # Log unexpected errors but don't show them if we have broken pipe
        _get_logger().error(f"Unexpected error: {e}")
        sys.exit(1)


def _main_impl():
    """Main implementation function."""
    parser = create_cli_parser()
    args = parser.parse_args()

    # Create system instance
    system = SMB2ReplaySystem()

    # Set verbosity
    if args.verbose:
        system.set_verbosity(min(args.verbose, 3))

    # Commands that don't need heavy dependencies can skip full setup
    lightweight_commands = {"config", "info"}

    if args.command in lightweight_commands:
        # Skip heavy setup for lightweight commands
        if not system.setup_system():
            _get_logger().error("System setup failed")
            sys.exit(1)
    else:
        # Full setup for commands that need tshark, session manager, etc.
        if not system.setup_system_full():
            _get_logger().error("System setup failed")
            sys.exit(1)

    # Handle commands
    if args.command == "ingest":
        pcap_path = resolve_pcap_path(args, system.config)
        if not pcap_path:
            safe_print("Error: No PCAP file specified. Use --help for usage.")
            sys.exit(1)

        result = system.ingest_pcap(
            pcap_path,
            force_reingest=args.force,
            reassembly=args.reassembly,
            verbose=args.verbose > 0,
        )
        if result:
            safe_print(
                f"Ingestion completed: {len(result['sessions'])} sessions extracted"
            )
        else:
            safe_print("Ingestion failed")
            sys.exit(1)

    elif args.command == "list":
        if not args.list_action:
            safe_print("List commands: traces")
            return

        if args.list_action == "traces":
            # Use case_id from command line arguments if provided
            case_id = args.case if hasattr(args, "case") and args.case else None

            # Update configuration if case_id is provided
            if case_id:
                system.config.set_case_id(case_id)

            traces = system.list_traces(case_id)

            # Get the case_id that was actually used (from args or config)
            actual_case_id = case_id or system.config.get_case_id()

            if not actual_case_id:
                safe_print("Error: Case ID must be configured to list traces.")
                safe_print(
                    "Use: smbreplay config set case_id <case_id> or provide --case argument"
                )
                return

            traces_folder = system.config.get_traces_folder()

            if traces:
                search_location = f"{traces_folder}/{actual_case_id}/"
                safe_print(
                    f"Available trace files in case {actual_case_id} ({len(traces)}):"
                )

                for trace in traces:
                    safe_print(f"  - {trace}")
            else:
                search_location = f"{traces_folder}/{actual_case_id}/"
                safe_print(
                    f"No trace files found in case {actual_case_id} folder: {search_location}"
                )

    elif args.command == "session":
        # Handle session listing
        if args.list:
            pcap_path = resolve_pcap_path(args, system.config)
            sessions = system.list_sessions(pcap_path)
            if sessions:
                safe_print(f"Available sessions ({len(sessions)}):")
                for session in sessions:
                    # Extract session ID from filename
                    if session.startswith("smb2_session_") and session.endswith(
                        ".parquet"
                    ):
                        session_id = session.replace("smb2_session_", "").replace(
                            ".parquet", ""
                        )
                        safe_print(f"  - {session_id}")
                    else:
                        safe_print(f"  - {session}")
            else:
                safe_print("No sessions found")
            return

        # Handle session ID resolution
        session_file = args.session_file
        session_id = args.session_id

        # If neither session_file nor session_id is provided, try to use configured session
        if not session_file and not session_id:
            session_id = system.config.get_session_id()
            if session_id:
                session_file = f"smb2_session_{session_id}.parquet"
                safe_print(f"Using configured session: {session_id}")
            else:
                safe_print("Error: No session file or session ID provided")
                safe_print(
                    "Use: smbreplay session <session_id> or smbreplay session --list to see available sessions"
                )
                sys.exit(1)

        # If session_file is provided and does not end with .parquet, treat as session ID
        if session_file and not session_file.endswith(".parquet"):
            session_id = session_file  # Store the original session ID
            # Only add prefix if not already prefixed (avoid smb2_session_smb2_session_*)
            if not session_file.startswith("smb2_session_"):
                session_file = f"smb2_session_{session_file}.parquet"
            else:
                session_file = f"{session_file}.parquet"

        # If --session-id is explicitly provided but session_file wasn't set from it above
        elif session_id and not session_file:
            if session_id.startswith("smb2_session_"):
                session_file = f"{session_id}.parquet"
            else:
                session_file = f"smb2_session_{session_id}.parquet"

        if not session_file:
            safe_print("Error: No session file or session ID provided")
            sys.exit(1)

        # Update configuration with session information
        if session_id:
            system.config.set_session_id(session_id)

        # Update case ID if provided
        if hasattr(args, "case") and args.case:
            system.config.set_case_id(args.case)

        # Update trace name if provided
        if hasattr(args, "trace") and args.trace:
            system.config.set_trace_name(args.trace)

        pcap_path = resolve_pcap_path(args, system.config)
        safe_print(f"Loading session: {session_file}")

        operations = system.get_session_info(
            session_file,
            capture_path=pcap_path,
            file_filter=args.file_filter,
            fields=args.fields,
        )

        if operations:
            safe_print(f"\nSession information: {len(operations)} operations found")
            safe_print("=" * 80)

            if args.brief:
                # Brief output - one line per frame
                safe_print(
                    f"{'#':<3} {'Frame':<6} {'Command':<25} {'Status':<20} {'Tree':<12} {'Path'}"
                )
                safe_print("-" * 80)

                for i, op in enumerate(operations, 1):
                    frame = op.get("Frame", "N/A")
                    command = op.get("Command", "Unknown")
                    path = op.get("Path", "N/A")
                    status = op.get("Status", "N/A")
                    tree = op.get("Tree", "N/A")

                    # Truncate long paths for brief display
                    if path != "N/A" and len(path) > 50:
                        path = "..." + path[-47:]

                    # Truncate long status messages
                    if status != "N/A" and len(status) > 18:
                        status = status[:15] + "..."

                    # Truncate long tree names
                    if tree != "N/A" and len(tree) > 10:
                        tree = tree[:7] + "..."

                    safe_print(
                        f"{i:<3} {frame:<6} {command:<25} {status:<20} {tree:<12} {path}"
                    )
            else:
                # Detailed output - multiple lines per operation
                for i, op in enumerate(operations, 1):
                    frame = op.get("Frame", "N/A")
                    command = op.get("Command", "Unknown")
                    path = op.get("Path", "N/A")
                    status = op.get("Status", "N/A")
                    tree = op.get("Tree", "N/A")

                    # Extract filename from path if it's not N/A
                    if path != "N/A" and "\\" in path:
                        filename = path.split("\\")[-1]
                        if filename:
                            display_path = f"{path} ({filename})"
                        else:
                            display_path = path
                    else:
                        display_path = path

                    safe_print(
                        f"{i:3d}. Frame {frame:>6} | {command:<25} | {display_path}"
                    )
                    safe_print(f"     Status: {status} | Tree: {tree}")

                    # Show additional fields if present
                    extra_fields = []
                    for key, value in op.items():
                        if key not in [
                            "Frame",
                            "Command",
                            "Path",
                            "Status",
                            "StatusDesc",
                            "Tree",
                            "orig_idx",
                        ]:
                            if (
                                value
                                and str(value).strip() != "N/A"
                                and str(value).strip() != ""
                            ):
                                extra_fields.append(f"{key}: {value}")

                    if extra_fields:
                        safe_print(f"     Additional: {' | '.join(extra_fields)}")

                    safe_print()  # Empty line between operations

        else:
            safe_print("Session analysis failed")
            sys.exit(1)

    elif args.command == "replay":
        # Handle session ID resolution (same logic as session command)
        session_file = args.session_file
        session_id = args.session_id

        # If session_file is provided and does not end with .parquet, treat as session ID and construct proper filename
        if session_file and not session_file.endswith(".parquet"):
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
                safe_print(f"Using configured session: {session_id}")
            else:
                safe_print("Error: No session specified and no session configured")
                safe_print(
                    "Use: smbreplay replay <session_id> or configure a session with 'smbreplay config set session_id <session_id>'"
                )
                sys.exit(1)

        # Update configuration with session information
        if session_id:
            system.config.set_session_id(session_id)

        # Update case ID if provided
        if hasattr(args, "case") and args.case:
            system.config.set_case_id(args.case)

        # Update trace name if provided
        if hasattr(args, "trace") and args.trace:
            system.config.set_trace_name(args.trace)

        # Configure replay if provided
        system.configure_replay(
            server_ip=args.server_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
            tree_name=args.tree_name,
        )

        # Get session info first
        pcap_path = resolve_pcap_path(args, system.config)
        safe_print(f"Loading session for replay: {session_file}")

        operations = system.get_session_info(
            session_file, capture_path=pcap_path, file_filter=args.file_filter
        )

        if not operations:
            safe_print("Failed to get session info for replay")
            sys.exit(1)

        safe_print(f"Loaded {len(operations)} operations for replay")

        # Configure ping settings
        from smbreplay.replay import get_replayer

        replayer = get_replayer()

        if hasattr(args, "no_ping") and args.no_ping:
            replayer.set_ping_enabled(False)
            safe_print("Ping disabled for this replay")
        else:
            replayer.set_ping_enabled(True)
            safe_print("Ping enabled - will ping replay server before starting")

        # Check if we should validate before replay
        if hasattr(args, "validate") and args.validate:
            safe_print("Validating replay readiness...")
            validation_result = system.validate_replay_readiness(operations)
            if not validation_result["ready"]:
                safe_print("❌ Validation failed - replay aborted")
                safe_print("Use 'smbreplay validate' to see detailed issues")
                sys.exit(1)
            safe_print("✅ Validation passed - proceeding with replay")

        # Replay operations
        result = system.replay_operations(operations)
        if result["success"]:
            safe_print(
                f"Replay completed successfully: {result['successful_operations']}/{result['total_operations']} operations"
            )
        else:
            safe_print(f"Replay failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)

    elif args.command == "validate":
        # Handle session ID resolution (same logic as replay command)
        session_file = args.session_file
        session_id = args.session_id

        # If session_file is provided and does not end with .parquet, treat as session ID and construct proper filename
        if session_file and not session_file.endswith(".parquet"):
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
                safe_print(f"Using configured session: {session_id}")
            else:
                safe_print("Error: No session specified and no session configured")
                safe_print(
                    "Use: smbreplay validate <session_id> or configure a session with 'smbreplay config set session_id <session_id>'"
                )
                sys.exit(1)

        # Update configuration with session information
        if session_id:
            system.config.set_session_id(session_id)

        # Update case ID if provided
        if hasattr(args, "case") and args.case:
            system.config.set_case_id(args.case)

        # Update trace name if provided
        if hasattr(args, "trace") and args.trace:
            system.config.set_trace_name(args.trace)

        # Configure replay if provided
        system.configure_replay(
            server_ip=args.server_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
            tree_name=args.tree_name,
        )

        # Get session info first
        pcap_path = resolve_pcap_path(args, system.config)
        safe_print(f"Loading session for validation: {session_file}")

        operations = system.get_session_info(
            session_file, capture_path=pcap_path, file_filter=args.file_filter
        )

        if not operations:
            safe_print("Failed to get session info for validation")
            sys.exit(1)

        safe_print(f"Loaded {len(operations)} operations for validation")

        # Determine what to check
        check_fs = args.check_fs or args.check_all or (not args.check_ops)
        check_ops = args.check_ops or args.check_all or (not args.check_fs)

        # Validate replay readiness
        validation_result = system.validate_replay_readiness(
            operations, check_fs=check_fs, check_ops=check_ops
        )

        # Display results
        safe_print("\n" + "=" * 60)
        safe_print("REPLAY VALIDATION RESULTS")
        safe_print("=" * 60)

        if validation_result["ready"]:
            safe_print("✅ REPLAY READY: All checks passed")
        else:
            safe_print("❌ REPLAY NOT READY: Issues found")

        # Show detailed results
        if "operations" in validation_result["checks"]:
            op_check = validation_result["checks"]["operations"]
            safe_print("\n📋 Operations Check:")
            safe_print(f"  Valid: {op_check.get('valid', False)}")
            safe_print(f"  Total operations: {op_check.get('total_operations', 0)}")
            safe_print(
                f"  Supported operations: {op_check.get('supported_operations', 0)}"
            )
            if op_check.get("issues"):
                safe_print(f"  Issues: {len(op_check['issues'])}")
                for issue in op_check["issues"][:5]:  # Show first 5 issues
                    safe_print(f"    - {issue}")
                if len(op_check["issues"]) > 5:
                    safe_print(f"    ... and {len(op_check['issues']) - 5} more")

        if "file_system" in validation_result["checks"]:
            fs_check = validation_result["checks"]["file_system"]
            safe_print("\n📁 File System Check:")
            safe_print(f"  Ready: {fs_check.get('ready', False)}")
            safe_print(f"  Total paths: {fs_check.get('total_paths', 0)}")
            safe_print(f"  Accessible paths: {fs_check.get('accessible_paths', 0)}")
            safe_print(f"  Files to create: {fs_check.get('created_files', 0)}")
            safe_print(f"  Files to open: {fs_check.get('existing_files', 0)}")

            missing_dirs = fs_check.get("missing_directories", [])
            if missing_dirs:
                safe_print(f"  Missing directories: {len(missing_dirs)}")
                for missing in missing_dirs[:5]:  # Show first 5
                    safe_print(f"    - {missing}")
                if len(missing_dirs) > 5:
                    safe_print(f"    ... and {len(missing_dirs) - 5} more")

            warnings = fs_check.get("warnings", [])
            if warnings:
                safe_print("  Warnings:")
                for warning in warnings:
                    safe_print(f"    - {warning}")

        # Show errors and warnings
        if validation_result["errors"]:
            safe_print("\n❌ Errors:")
            for error in validation_result["errors"]:
                safe_print(f"  {error}")

        if validation_result["warnings"]:
            safe_print("\n⚠️  Warnings:")
            for warning in validation_result["warnings"]:
                safe_print(f"  {warning}")

        # Exit with appropriate code
        if not validation_result["ready"]:
            safe_print("\n💡 To fix issues:")
            safe_print("  - Check SMB server configuration")
            safe_print("  - Ensure required directories exist")
            safe_print("  - Verify operation compatibility")
            sys.exit(1)
        else:
            safe_print(f"\n🎉 Ready to replay! Use: smbreplay replay {session_id}")

    elif args.command == "setup":
        # Handle session ID resolution (same logic as validate command)
        session_file = args.session_file
        session_id = args.session_id

        # If session_file is provided and does not end with .parquet, treat as session ID and construct proper filename
        if session_file and not session_file.endswith(".parquet"):
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
                safe_print(f"Using configured session: {session_id}")
            else:
                safe_print("Error: No session specified and no session configured")
                safe_print(
                    "Use: smbreplay setup <session_id> or configure a session with 'smbreplay config set session_id <session_id>'"
                )
                sys.exit(1)

        # Update configuration with session information
        if session_id:
            system.config.set_session_id(session_id)

        # Update case ID if provided
        if hasattr(args, "case") and args.case:
            system.config.set_case_id(args.case)

        # Update trace name if provided
        if hasattr(args, "trace") and args.trace:
            system.config.set_trace_name(args.trace)

        # Configure replay if provided
        system.configure_replay(
            server_ip=args.server_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
            tree_name=args.tree_name,
        )

        # Get session info first
        pcap_path = resolve_pcap_path(args, system.config)
        safe_print(f"Loading session for setup: {session_file}")

        operations = system.get_session_info(
            session_file, capture_path=pcap_path, file_filter=args.file_filter
        )

        if not operations:
            safe_print("Failed to get session info for setup")
            sys.exit(1)

        safe_print(f"Loaded {len(operations)} operations for setup")

        # Setup file system infrastructure
        setup_result = system.setup_file_system_infrastructure(
            operations, dry_run=args.dry_run, force=args.force
        )

        if not setup_result["success"]:
            safe_print("❌ Setup failed")
            if not args.dry_run:
                safe_print("💡 Try running with --dry-run to see what would be created")
                safe_print("💡 Try running with --force to continue despite errors")
            sys.exit(1)
        else:
            safe_print("✅ Setup completed successfully")
            if not args.dry_run:
                safe_print(f"💡 You can now run: smbreplay validate {session_id}")
                safe_print(f"💡 Or proceed with: smbreplay replay {session_id}")

    elif args.command == "config":
        handle_config_command(args, system.config)

    elif args.command == "info":
        info = system.get_system_info()
        safe_print("SMB2 Replay System Status:")
        safe_print("  Version: 1.0.0")
        safe_print(f"  TShark available: {info['tshark_available']}")
        safe_print(
            f"  Supported commands: {', '.join(info['supported_commands'].values())}"
        )

        # Show current active configuration
        current_pcap = info.get("capture_path")
        if current_pcap:
            safe_print(f"  Current PCAP: {current_pcap}")
            if info.get("packet_count"):
                safe_print(f"  Packet count: {info['packet_count']}")
        else:
            safe_print("  No PCAP currently loaded")

    elif args.command is None:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
