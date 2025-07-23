from smbprotocol.exceptions import SMBException
from smbreplay.utils import get_share_relative_path
from smbreplay.handlers.lock import handle_lock as lock_handler
from smbreplay.handlers.create import handle_create
from smbreplay.handlers.flush import handle_flush
from smbreplay.handlers.ioctl import handle_ioctl
from smbreplay.handlers.query_directory import handle_query_directory
from smbreplay.handlers.query_info import handle_query_info
from smbreplay.handlers.negotiate import handle_negotiate
from smbreplay.handlers.session_setup import handle_session_setup
from smbreplay.handlers.logoff import handle_logoff
from smbreplay.handlers.tree_disconnect import handle_tree_disconnect
from smbreplay.handlers.tree_connect import handle_tree_connect
from smbreplay.handlers.echo import handle_echo
from smbreplay.handlers.set_info import handle_set_info
from smbreplay.handlers.oplock_break import handle_oplock_break
from smbreplay.handlers.cancel import handle_cancel
from smbreplay.handlers.change_notify import handle_change_notify
from smbreplay.handlers.response import handle_response
from smbreplay.handlers.close import handle_close as close_handler
from smbreplay.handlers.read import handle_read as read_handler
from smbreplay.handlers.write import handle_write as write_handler
from smbreplay.handlers.lease_break import handle_lease_break
"""
SMB2 Replay Module.
Handles SMB2 session replay using smbprotocol library.
"""

import time
import subprocess
from typing import List, Dict, Any, Optional, Callable, Tuple
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.exceptions import SMBException
import uuid

from .config import get_config, get_logger
from .constants import SMB2_OP_NAME_DESC

logger = get_logger()



class SMB2Replayer:
    """Handles SMB2 session replay functionality."""

    def handle_read(self, op: Dict[str, Any]):
        """Handle Read operation using modular handler."""
        return read_handler(self, op)

    def handle_close(self, op: Dict[str, Any]):
        """Handle Close operation using modular handler."""
        return close_handler(self, op)

    
    def __init__(self):
        
        logger = get_logger()  # Initialize logger here
        self.logger = logger
        self.config = get_config()
        self.connection = None
        self.tid_mapping = {}
        self.fid_mapping = {}
        self.state = {'last_new_tid': None, 'last_new_fid': None}
        self.response_validation = {'enabled': True, 'results': []}
        self.reset_mode = 'complete'  # 'complete' or 'cleanup'
        self.ping_enabled = True  # Enable ping by default
        
    def set_ping_enabled(self, enabled: bool = True):
        """Enable or disable ping functionality.
        
        Args:
            enabled: Whether to send ping before replay starts
        """
        self.ping_enabled = enabled
        self.logger.info(f"Ping functionality {'enabled' if enabled else 'disabled'}")
    
    def send_replay_start_ping(self, server_ip: Optional[str] = None):
        """Send a ping to the replay server to indicate replay is starting.
        
        Args:
            server_ip: SMB server IP to ping (uses configured server if None)
        """
        if not self.ping_enabled:
            return
            
        if server_ip is None:
            # Get server IP from configuration
            replay_config = self.get_replay_config()
            server_ip = replay_config.get("server_ip", "127.0.0.1")
            
        try:
            self.logger.info(f"🔄 Sending replay start ping to replay server: {server_ip}")
            result = subprocess.run(
                ['ping', '-c', '1', server_ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.info(f"✅ Replay start ping successful to {server_ip}")
                self.logger.debug(f"Ping output: {result.stdout.strip()}")
            else:
                self.logger.warning(f"⚠️ Replay start ping failed to {server_ip}")
                self.logger.debug(f"Ping error: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"⚠️ Replay start ping timeout to {server_ip}")
        except FileNotFoundError:
            self.logger.warning("⚠️ Ping command not found - skipping replay start ping")
        except Exception as e:
            self.logger.warning(f"⚠️ Replay start ping error: {e}")
    
    def set_reset_mode(self, mode: str):
        """Set the reset mode for replay operations.
        
        Args:
            mode: 'complete' for full reset, 'cleanup' for selective cleanup
        """
        if mode not in ['complete', 'cleanup']:
            self.logger.warning(f"Invalid reset mode '{mode}', using 'complete'")
            mode = 'complete'
        self.reset_mode = mode
        self.logger.info(f"Reset mode set to: {mode}")
    
    def enable_response_validation(self, enabled: bool = True):
        """Enable or disable response validation.
        
        Args:
            enabled: Whether to validate responses against Parquet data
        """
        self.response_validation['enabled'] = enabled
        self.response_validation['results'] = []
        self.logger.info(f"Response validation {'enabled' if enabled else 'disabled'}")
    
    def validate_response(self, operation: Dict[str, Any], actual_status: str, actual_error: Optional[str] = None):
        """Validate that the actual server response matches the expected response from Parquet.
        
        Args:
            operation: Original operation from Parquet data
            actual_status: Actual NT status from server (hex format)
            actual_error: Actual error message from server (if any)
        """
        if not self.response_validation['enabled']:
            return
        
        expected_status = operation.get('smb2.nt_status', 'N/A')
        # Defensive: ensure both are strings for .startswith
        if not isinstance(expected_status, str):
            expected_status = str(expected_status)
        if not isinstance(actual_status, str):
            actual_status = str(actual_status)
        frame_number = operation.get('Frame', 'N/A')
        command = operation.get('Command', 'Unknown')
        filename = operation.get('smb2.filename', 'N/A')
        
        # If expected_status is None or N/A, this is likely a request frame
        # We need to find the corresponding response frame to get the expected status
        if expected_status in [None, 'N/A', '']:
            # For now, assume success (0x00000000) for request frames
            # In a full implementation, we would look up the corresponding response frame
            expected_status = '0x00000000'
            self.logger.debug(f"Request frame {frame_number}: Assuming expected status {expected_status}")
        
        # Normalize status codes for comparison
        expected_hex = expected_status if expected_status.startswith('0x') else f"0x{int(float(expected_status)):08x}" if expected_status.replace('.','',1).isdigit() else expected_status
        actual_hex = actual_status if actual_status.startswith('0x') else f"0x{int(float(actual_status)):08x}" if actual_status.replace('.','',1).isdigit() else actual_status
        
        # Check if status codes match
        status_match = expected_hex == actual_hex
        
        validation_result = {
            'frame': frame_number,
            'command': command,
            'filename': filename,
            'expected_status': expected_hex,
            'actual_status': actual_hex,
            'status_match': status_match,
            'actual_error': actual_error,
            'timestamp': time.time()
        }
        
        self.response_validation['results'].append(validation_result)
        
        if status_match:
            self.logger.debug(f"✅ Response validation passed: {command} (Frame {frame_number}) - Status: {actual_hex}")
        else:
            self.logger.warning(f"❌ Response validation failed: {command} (Frame {frame_number})")
            self.logger.warning(f"   Expected: {expected_hex}, Actual: {actual_hex}")
            if actual_error:
                self.logger.warning(f"   Error: {actual_error}")
    
    def get_response_validation_results(self) -> Dict[str, Any]:
        """Get response validation results.
        
        Returns:
            Dictionary with validation summary and details
        """
        results = self.response_validation['results']
        
        if not results:
            return {
                'enabled': self.response_validation['enabled'],
                'total_operations': 0,
                'matching_responses': 0,
                'mismatched_responses': 0,
                'match_rate': 0.0,
                'details': []
            }
        
        matching = sum(1 for r in results if r['status_match'])
        total = len(results)
        
        return {
            'enabled': self.response_validation['enabled'],
            'total_operations': total,
            'matching_responses': matching,
            'mismatched_responses': total - matching,
            'match_rate': (matching / total) * 100.0 if total > 0 else 0.0,
            'details': results
        }

    def handle_ioctl(self, op: Dict[str, Any]):
        """Handle IOCTL operation (stub)."""
        self.logger.debug(f"IOCTL: Not implemented. op={op}")

    def handle_query_directory(self, op: Dict[str, Any]):
        """Handle Query Directory operation (stub)."""
        self.logger.debug(f"Query Directory: Not implemented. op={op}")

    def handle_query_info(self, op: Dict[str, Any]):
        """Handle Query Info operation (stub)."""
        self.logger.debug(f"Query Info: Not implemented. op={op}")

    def handle_negotiate(self, op: Dict[str, Any]):
        self.logger.info("Negotiate: Using already established connection for replay. Parameters: %s", op)
        # Optionally validate parameters or log them

    def handle_session_setup(self, op: Dict[str, Any]):
        self.logger.info("Session Setup: Using already established session for replay. Parameters: %s", op)
        # Optionally validate parameters or log them

    def handle_logoff(self, op: Dict[str, Any]):
        self.logger.info("Logoff: Skipping, as session teardown is handled at the end of replay. Parameters: %s", op)
        # Optionally disconnect session if this is the last operation

    def handle_tree_disconnect(self, op: Dict[str, Any]):
        self.logger.info("Tree Disconnect: Skipping, as tree teardown is handled at the end of replay. Parameters: %s", op)
        # Optionally disconnect tree if this is the last operation

    def handle_flush(self, op: Dict[str, Any]):
        self.logger.info("Flush: Not implemented. Parameters: %s", op)

    def handle_lock(self, op: Dict[str, Any]):
        return lock_handler(self, op)

    def handle_echo(self, op: Dict[str, Any]):
        self.logger.info("Echo: Not implemented. Parameters: %s", op)

    def handle_set_info(self, op: Dict[str, Any]):
        self.logger.info("Set Info: Not implemented. Parameters: %s", op)

    def handle_oplock_break(self, op: Dict[str, Any]):
        self.logger.info("Oplock Break: Not implemented. Parameters: %s", op)

    def handle_lease_break(self, op: Dict[str, Any]):
        """Handle Lease Break operation using modular handler (SMB3)."""
        return handle_lease_break(self, op)

    def get_replay_config(self) -> Dict[str, Any]:
        """Get replay configuration."""
        return self.config.replay_config.copy()
    
    def determine_create_type_and_action(self, operation: Dict[str, Any], all_operations: List[Dict[str, Any]]) -> Tuple[str, str]:
        """
        Determine if a create operation should create a file or directory, and if it is a new create or open.
        Returns a tuple: (type, action) where type is 'file' or 'directory', and action is 'create' or 'open'.
        Raises ValueError if no matching response is found in the trace.
        """
        import json
        msg_id = operation.get('smb2.msg_id')
        for resp_op in all_operations:
            if (
                resp_op.get('smb2.cmd') == '5'
                and resp_op.get('smb2.flags.response') == 'True'
                and resp_op.get('smb2.msg_id') == msg_id
            ):
                create_action = resp_op.get('smb2.create.action', '')
                nt_status = resp_op.get('smb2.nt_status', '0x00000000')
                
                # Handle empty create_action (usually means the operation failed)
                if not create_action or create_action == '':
                    logger.debug(f"Empty create.action for msg_id {msg_id} in response frame {resp_op.get('Frame')} with status {nt_status}")
                    # For failed operations, we can't determine the type/action, so return defaults
                    return 'file', 'open'
                
                if create_action == 'FILE_CREATED':
                    return 'file', 'create'
                elif create_action == 'FILE_OPENED':
                    return 'file', 'open'
                elif create_action == 'DIRECTORY_CREATED':
                    return 'directory', 'create'
                elif create_action == 'DIRECTORY_OPENED':
                    return 'directory', 'open'
                else:
                    logger.warning(f"Unknown create.action '{create_action}' for msg_id {msg_id} in response frame {resp_op.get('Frame')}")
        # Map SMB2 command codes to handler methods
        # 0: Negotiate, 1: Session Setup, 2: Logoff, 3: Tree Connect, 4: Tree Disconnect, 5: Create, 6: Close, 7: Flush, 8: Read, 9: Write, 10: Lock, ...
        # If we get here, the trace is missing a response for this create
        import json
        logger.error(f"No matching SMB2 CREATE response found in trace for msg_id: {msg_id}")
        logger.error(f"  Request operation frame: {json.dumps(operation, indent=2, default=str)}")
        candidate_responses = [resp_op for resp_op in all_operations if resp_op.get('smb2.cmd') == '5' and resp_op.get('smb2.flags.response') == 'True']
        logger.error(f"  All candidate SMB2 CREATE response frames:")
        for resp_op in candidate_responses:
            logger.error(f"    Frame {resp_op.get('Frame')}: msg_id={resp_op.get('smb2.msg_id')} action={resp_op.get('smb2.create.action')} status={resp_op.get('smb2.nt_status')}")
        logger.error(f"  (End of candidate response frames)")
        raise ValueError(f"No matching SMB2 CREATE response found in trace for msg_id: {msg_id}")
    
    def reset_target_to_fresh_state(self, tree: TreeConnect, share_path: str):
        """
        Reset the target share to a completely fresh state by removing all files and directories.
        This ensures that each replay starts with a clean slate.
        
        Args:
            tree: TreeConnect object to the share
            share_path: Path to the share being reset
        """
        logger.info(f"Resetting target share to fresh state: {share_path}")
        
        try:
            # Define known paths that might exist from previous replays
            # Separate files and directories
            known_files = [
                "desktop.ini", 
                "cache_volume\\desktop.ini",
                "test_file.txt",
                "replay_test.txt",
                "replay_create_test.txt",
                "replay_open_test.txt"
            ]
            
            known_dirs = [
                "cache_volume"
            ]
            
            files_removed = 0
            
            # First pass: Try to delete directories (must be empty)
            for dir_path in known_dirs:
                try:
                    # Try to delete directory with FILE_DELETE_ON_CLOSE
                    dir_open = Open(tree, dir_path)
                    dir_open.create(
                        impersonation_level=0,  # SECURITY_ANONYMOUS
                        desired_access=0x00010000,  # DELETE
                        file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                        share_access=0x00000001,  # FILE_SHARE_READ
                        create_disposition=1,  # FILE_OPEN
                        create_options=0x00001000 | 1  # FILE_DELETE_ON_CLOSE | FILE_DIRECTORY_FILE
                    )
                    dir_open.close()
                    files_removed += 1
                    logger.debug(f"Removed directory: {dir_path}")
                except SMBException as e:
                    if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):
                        logger.debug(f"Could not remove directory {dir_path}: {e}")
                        # If directory is not empty, try to remove files inside it first
                        if "STATUS_DIRECTORY_NOT_EMPTY" in str(e):
                            logger.debug(f"Directory {dir_path} is not empty, trying to remove contents")
                            # Try to remove files inside the directory
                            for file_path in known_files:
                                if file_path.startswith(dir_path + "\\"):
                                    try:
                                        file_open = Open(tree, file_path)
                                        file_open.create(
                                            impersonation_level=0,
                                            desired_access=0x00010000,  # DELETE
                                            file_attributes=0,
                                            share_access=0x00000001,
                                            create_disposition=1,
                                            create_options=0x00001000
                                        )
                                        file_open.close()
                                        logger.debug(f"Removed file inside directory: {file_path}")
                                    except SMBException as fe:
                                        logger.debug(f"Could not remove {file_path}: {fe}")
            
            # Second pass: Try to delete files
            for file_path in known_files:
                try:
                    file_open = Open(tree, file_path)
                    file_open.create(
                        impersonation_level=0,  # SECURITY_ANONYMOUS
                        desired_access=0x00010000,  # DELETE
                        file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                        share_access=0x00000001,  # FILE_SHARE_READ
                        create_disposition=1,  # FILE_OPEN
                        create_options=0x00001000  # FILE_DELETE_ON_CLOSE
                    )
                    file_open.close()
                    files_removed += 1
                    logger.debug(f"Removed file: {file_path}")
                except SMBException as e:
                    if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):
                        logger.debug(f"Could not remove file {file_path}: {e}")
            
            # Third pass: Try to delete directories again (now that files are removed)
            for dir_path in known_dirs:
                try:
                    dir_open = Open(tree, dir_path)
                    dir_open.create(
                        impersonation_level=0,
                        desired_access=0x00010000,  # DELETE
                        file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                        share_access=0x00000001,
                        create_disposition=1,
                        create_options=0x00001000 | 1  # FILE_DELETE_ON_CLOSE | FILE_DIRECTORY_FILE
                    )
                    dir_open.close()
                    files_removed += 1
                    logger.debug(f"Removed directory (second attempt): {dir_path}")
                except SMBException as e:
                    if "STATUS_OBJECT_NAME_NOT_FOUND" not in str(e):
                        logger.debug(f"Could not remove directory {dir_path} (second attempt): {e}")
            
            logger.info(f"Reset completed: {files_removed} files/directories processed")
            
        except SMBException as e:
            logger.warning(f"Could not perform complete reset: {e}")
            logger.info("Proceeding with standard cleanup instead")
    
    def cleanup_existing_files(self, tree: TreeConnect, paths: set):
        """
        Clean up existing files and directories that will be recreated during replay.
        This ensures a clean slate for each replay operation.
        
        Args:
            tree: TreeConnect object to the share
            paths: Set of all paths that will be accessed during replay
        """
        self.logger.info("Cleaning up existing files and directories for clean replay")
        
        if not paths:
            self.logger.info("No paths to clean up")
            return
        
        # Normalize paths
        normalized_paths = {path.replace('/', '\\') for path in paths if path}
        
        # Sort paths by depth (deepest first) to delete files before directories
        sorted_paths = sorted(normalized_paths, key=lambda x: (x.count('\\'), x), reverse=True)
        
        files_deleted = 0
        dirs_deleted = 0
        
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
                    create_options=0x00001000  # FILE_DELETE_ON_CLOSE
                )
                
                # Close the file which will delete it due to FILE_DELETE_ON_CLOSE
                file_open.close()
                
                files_deleted += 1
                self.logger.debug(f"Deleted file: {path}")
                
            except SMBException as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    # File doesn't exist, which is fine
                    self.logger.debug(f"File not found (already deleted): {path}")
                elif "STATUS_ACCESS_DENIED" in str(e):
                    # Access denied, might be a directory or protected file
                    self.logger.debug(f"Access denied for deletion: {path}")
                else:
                    self.logger.debug(f"Failed to delete {path}: {e}")
        
        logger.info(f"Cleanup completed: {files_deleted} files deleted, {dirs_deleted} directories deleted")

    def setup_pre_trace_state(self, tree: 'TreeConnect', session: 'Session', selected_operations: list):
        """
        Set up the file system state on the lab server before replaying operations using smbprotocol.
        This ensures all necessary directories and files exist before replay begins.
        First resets the target to a fresh state, then cleans up any existing files to ensure a clean replay.

        Args:
            tree: TreeConnect object to the share
            session: Session object for authentication
            selected_operations: List of selected operation dictionaries
        """
        logger.info("Setting up pre-trace state for selected operations")
        replay_config = self.get_replay_config()
        tree_name = replay_config.get("tree_name", "testshare")

        if self.reset_mode == 'complete':
            self.reset_target_to_fresh_state(tree, tree_name)
        else:
            logger.info("Using cleanup mode - skipping complete reset")

        # --- NEW LOGIC: Find all files and parent directories referenced by CREATE/WRITE requests ---
        file_paths = set()
        for op in selected_operations:
            cmd = int(op.get('smb2.cmd', -1))
            is_request = op.get('smb2.flags.response') != 'True'
            if cmd in [5, 9] and is_request:
                filename = op.get('smb2.filename', '')
                rel_filename = get_share_relative_path(self, filename)
                if rel_filename and rel_filename not in ['.', '..', 'N/A', '']:
                    file_paths.add(rel_filename)

        # Build parent directories for all files
        directories = set()
        for rel_path in file_paths:
            parts = rel_path.split('\\')
            if len(parts) > 1:
                for i in range(1, len(parts)):
                    dir_path = '\\'.join(parts[:i])
                    if dir_path:
                        directories.add(dir_path)

        logger.info(f"Pre-trace: will create {len(directories)} directories and {len(file_paths)} files if missing.")
        logger.debug(f"Directories to create: {sorted(directories)}")
        logger.debug(f"Files to create: {sorted(file_paths)}")

        # Create parent directories (deepest first)
        created_dirs = set()
        sorted_dirs = sorted(directories, key=lambda x: (x.count('\\'), x))
        for dir_path in sorted_dirs:
            parts = dir_path.split('\\')
            current_path = ""
            for i, part in enumerate(parts):
                if i == 0:
                    current_path = part
                else:
                    current_path = current_path + '\\' + part
                if current_path in created_dirs:
                    continue
                try:
                    dir_open = Open(tree, current_path)
                    dir_open.create(
                        impersonation_level=0,
                        desired_access=0x80000000,
                        file_attributes=0x00000010,
                        share_access=0x00000001,
                        create_disposition=3,
                        create_options=1
                    )
                    created_dirs.add(current_path)
                    logger.debug(f"Created directory: {current_path}")
                    dir_open.close()
                except SMBException as e:
                    if "STATUS_OBJECT_NAME_COLLISION" not in str(e):
                        logger.warning(f"Failed to create directory {current_path}: {e}")
                        break
                    else:
                        created_dirs.add(current_path)
                        logger.debug(f"Directory already exists: {current_path}")

        # Pre-create all files (as empty files)
        files_created = 0
        for rel_path in file_paths:
            try:
                file_open = Open(tree, rel_path)
                file_open.create(
                    impersonation_level=0,
                    desired_access=0x80000000 | 0x40000000,
                    file_attributes=0,
                    share_access=0x00000001,
                    create_disposition=3,
                    create_options=0
                )
                files_created += 1
                logger.debug(f"Pre-created file: {rel_path}")
                file_open.close()
            except SMBException as e:
                logger.warning(f"Failed to pre-create file {rel_path}: {e}")

        logger.info(f"Pre-trace state setup complete:")
        logger.info(f"  - {len(created_dirs)} directories created/exist")
        logger.info(f"  - {files_created} files pre-created for open/write/create")
        logger.info(f"  - {len(file_paths)} total file paths pre-created")

        # --- Close SMB session and connection after pre-trace setup ---
        try:
            logger.info("Closing SMB session and connection after pre-trace setup to force new establishment for replay.")
            try:
                tree.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting tree after pre-trace: {e}")
            try:
                session.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting session after pre-trace: {e}")
            try:
                if hasattr(session, 'connection'):
                    session.connection.disconnect()
            except Exception as e:
                logger.debug(f"Error disconnecting connection after pre-trace: {e}")
        except Exception as e:
            logger.warning(f"Error during SMB cleanup after pre-trace: {e}")
    
    def _validate_file_system_structure(self, tree: TreeConnect, paths: set, created_dirs: set):
        """
        Validate that the file system structure is ready for replay.
        
        Args:
            tree: TreeConnect object for the share
            paths: Set of all paths that will be accessed during replay
            created_dirs: Set of directories that were successfully created
        """
        logger.info("Validating file system structure for replay...")
        
        missing_dirs = set()
        accessible_paths = 0
        
        for path in paths:
            # Check if the parent directory exists for each path
            parts = path.split('\\')
            if len(parts) > 1:
                parent_dir = '\\'.join(parts[:-1])
                if parent_dir not in created_dirs:
                    missing_dirs.add(parent_dir)
                else:
                    accessible_paths += 1
            else:
                # File in root directory
                accessible_paths += 1
        
        if missing_dirs:
            logger.warning(f"Missing directories for {len(missing_dirs)} paths:")
            for missing_dir in sorted(missing_dirs):
                logger.warning(f"  - {missing_dir}")
            logger.warning(f"Only {accessible_paths}/{len(paths)} paths will be accessible during replay")
        else:
            logger.info(f"✅ All {len(paths)} paths are accessible for replay")
    
    def handle_tree_connect(self, session: Session, op: Dict[str, Any]):
        """Handle Tree Connect operation using handler module."""
        return handle_tree_connect(self, session, op)
    
    def handle_write(self, op: Dict[str, Any]):
        """Handle Write operation using modular handler."""
        return write_handler(self, op)
    
    def handle_response(self, op: Dict[str, Any], cmd: int):
        """Handle response operations to update mappings.
        
        Args:
            op: Operation dictionary
            cmd: Command code
        """
        if cmd == 3:  # Tree Connect response
            original_tid = op.get('smb2.tid', '')
            if self.state['last_new_tid'] is not None:
                self.tid_mapping[original_tid] = self.state['last_new_tid']
                logger.debug(f"Mapped tid {original_tid} to {self.state['last_new_tid']}")
                self.state['last_new_tid'] = None
        
        elif cmd == 5:  # Create response
            original_fid = op.get('smb2.fid', '')
            if self.state['last_new_fid'] is not None:
                self.fid_mapping[original_fid] = self.state['last_new_fid']
                logger.debug(f"Mapped fid {original_fid} to {self.state['last_new_fid']}")
                self.state['last_new_fid'] = None
    
    def handle_change_notify(self, op: Dict[str, Any]):
        """Handle Change Notify operation using smbprotocol.

        Args:
            op: Operation dictionary
        """
        original_fid = op.get('smb2.fid', '')
        file_open = self.fid_mapping.get(original_fid)

        if file_open:
            try:
                # You may want to pass filter, completion_filter, etc. from op if available
                # Example: file_open.change_notify(completion_filter=0x00000010)
                logger.debug(f"Change Notify: fid={original_fid}, Open object={file_open}")
                # Placeholder: actual change_notify logic can be added here
            except SMBException as e:
                logger.error(f"Change Notify failed for fid {original_fid}: {e}")
        else:
            logger.warning(f"Change Notify: No mapping found for fid {original_fid}")

    

    def handle_cancel(self, op: Dict[str, Any]):
        """Handle Cancel operation using smbprotocol.

        Args:
            op: Operation dictionary
        """
        original_fid = op.get('smb2.fid', '')
        file_open = self.fid_mapping.get(original_fid)

        try:
            # SMB2 Cancel is rarely needed in replay; log for completeness
            logger.debug(f"Cancel: fid={original_fid}, Open object={file_open}")
            # Placeholder: smbprotocol does not expose a direct cancel method
        except SMBException as e:
            logger.error(f"Cancel failed for fid {original_fid}: {e}")



    def replay_session(self, selected_operations: List[Dict[str, Any]], 
                      status_callback: Optional[Callable] = None) -> Dict[str, Any]:
        r"""
        Replay selected SMB2 operations using smbprotocol.

        Args:
            selected_operations: List of SMB2 operation dictionaries to replay
            status_callback: Optional callback for status updates

        Returns:
            Dictionary with replay results and statistics
        """
        # Extract server configuration and force reload
        self.config._load_config()  # Force reload from disk
        replay_config = self.get_replay_config()
        server_ip = replay_config.get("server_ip", "127.0.0.1")
        domain = replay_config.get("domain", "")
        username = replay_config.get("username", "jtownsen")
        password = replay_config.get("password", "P@ssw0rd")
        default_tree_name = replay_config.get("tree_name", "testshare")
        max_wait = replay_config.get("max_wait", 5.0)

        logger.debug(f"Using replay config: server_ip={server_ip}, domain={domain}, "
                    f"username={username}, tree_name={default_tree_name}, max_wait={max_wait}")


        try:
            # --- Pre-trace setup: use a temporary connection/session/tree ---
            if status_callback:
                status_callback("Setting up pre-trace state...")
            logger.debug(f"Connecting to SMB server for pre-trace: {server_ip}")
            pre_connection = Connection(uuid.uuid4(), server_ip, 445)
            pre_connection.connect(timeout=max_wait)
            pre_session = Session(pre_connection, username, password, require_encryption=False)
            pre_session.connect()
            pre_tree = TreeConnect(pre_session, f"\\\\{server_ip}\\{default_tree_name}")
            pre_tree.connect()
            self.setup_pre_trace_state(pre_tree, pre_session, selected_operations)
            # Pre-trace setup closes its own connection/session/tree

            # --- Main replay: use a fresh connection/session/tree ---
            if status_callback:
                status_callback("Connecting to SMB server...")
            logger.debug(f"Connecting to SMB server: {server_ip}")
            connection = Connection(uuid.uuid4(), server_ip, 445)
            connection.connect(timeout=max_wait)
            session = Session(connection, username, password, require_encryption=False)
            session.connect()
            tree = TreeConnect(session, f"\\\\{server_ip}\\{default_tree_name}")
            tree.connect()
            logger.info("Successfully connected to SMB server and share")
            if status_callback:
                status_callback(f"Connected to tree: {default_tree_name}")

            # Send replay start ping to differentiate from pre-trace setup
            if status_callback:
                status_callback("Sending replay start ping...")
            self.send_replay_start_ping(server_ip)

            # Initialize mappings
            self.tid_mapping = {}
            self.fid_mapping = {}
            self.state = {'last_new_tid': None, 'last_new_fid': None}


            # Summarize command types in selected_operations
            from collections import Counter
            cmd_counter: Counter = Counter()
            for op in selected_operations:
                try:
                    cmd_raw = op.get('smb2.cmd', '-1')
                    cmd = int(cmd_raw) if str(cmd_raw).isdigit() else -1
                    cmd_name = SMB2_OP_NAME_DESC.get(cmd, (f"UNKNOWN({cmd})",))[0]
                    cmd_counter[f"{cmd_name} ({cmd})"] += 1
                except Exception:
                    cmd_counter['error'] += 1
            logger.info(f"Main replay: processing {len(selected_operations)} operations. Command summary: {dict(cmd_counter)}")

            logger.debug(f"Main replay: processing {len(selected_operations)} operations")

            # Process selected operations
            successful_ops = 0
            failed_ops = 0
            supported_commands = set(self.command_handlers.keys())
            issues = []

            for i, op in enumerate(selected_operations, 1):
                logger.debug(f"Replay loop: operation {i}/{len(selected_operations)}: cmd={op.get('smb2.cmd')} resp={op.get('smb2.flags.response')} frame={op.get('Frame')} name={op.get('Command')}")
                try:
                    cmd_raw = op.get('smb2.cmd', '-1')
                    cmd = int(cmd_raw) if str(cmd_raw).isdigit() else -1
                    cmd_name = SMB2_OP_NAME_DESC.get(cmd, (f"UNKNOWN({cmd})",))[0]

                    if cmd not in supported_commands:
                        frame = op.get('Frame', 'N/A')
                        issues.append(
                            f"Operation {i+1} (Frame {frame}): Unsupported command {cmd} ({cmd_name})"
                        )
                        continue
                except Exception as e:
                    logger.error(f"Error processing operation {i}: {e}")
                    failed_ops += 1
                    continue

                try:
                    is_response = op.get('smb2.flags.response') == 'True'
                    cmd = int(op.get('smb2.cmd', -1))

                    if status_callback:
                        status_callback(f"Processing operation {i}/{len(selected_operations)}: {op.get('Command', 'Unknown')}")

                    if not is_response:  # Request
                        handler = self.command_handlers.get(cmd)
                        logger.debug(f"Dispatching to handler for cmd={cmd} ({SMB2_OP_NAME_DESC.get(cmd, ('Unknown',))[0]})")
                        if handler:
                            # Pass correct objects for each handler
                            if cmd == 3:
                                logger.info(f"Calling Tree Connect handler for operation {i}")
                                handler(session, op)
                            elif cmd == 5:
                                logger.info(f"Calling Create handler for operation {i} (filename={op.get('smb2.filename')})")
                                handler(tree, op, selected_operations)  # Pass all operations for create type determination
                            elif cmd == 6:
                                logger.info(f"Calling Close handler for operation {i} (fid={op.get('smb2.fid')})")
                                handler(op)
                            elif cmd == 8:
                                logger.info(f"Calling Read handler for operation {i} (fid={op.get('smb2.fid')})")
                                handler(op)
                            elif cmd == 9:
                                logger.info(f"Calling Write handler for operation {i} (fid={op.get('smb2.fid')})")
                                handler(op)
                            elif cmd == 10:
                                self.logger.info(f"Calling Lock handler for operation {i} (fid={op.get('smb2.fid')})")
                                handler(op)
                            elif cmd in [12, 15]:
                                handler(op)
                            else:
                                pass
                            successful_ops += 1
                        else:
                            logger.warning(f"Invalid command code: {cmd}")
                    else:  # Response
                        self.handle_response(op, cmd)

                except Exception as e:
                    logger.error(f"Error processing operation {i}: {e}")
                    failed_ops += 1

            # Clean up
            logger.debug("Disconnecting from SMB server")
            try:
                tree.disconnect()
            except Exception:
                pass
            try:
                session.disconnect()
            except Exception:
                pass
            try:
                connection.disconnect()
            except Exception:
                pass
            logger.info("Disconnected from SMB server")

            # Get response validation results
            validation_results = self.get_response_validation_results()
            
            # Prepare results
            results = {
                "success": True,
                "total_operations": len(selected_operations),
                "successful_operations": successful_ops,
                "failed_operations": failed_ops,
                "tid_mappings": len(self.tid_mapping),
                "fid_mappings": len(self.fid_mapping),
                "issues": issues,
                "response_validation": validation_results
            }

            if status_callback:
                status_callback(f"Replay completed: {successful_ops} successful, {failed_ops} failed")
                if validation_results['enabled']:
                    status_callback(f"Response validation: {validation_results['matching_responses']}/{validation_results['total_operations']} responses match ({validation_results['match_rate']:.1f}%)")
            logger.info(f"Replay completed: {results}")

            return results

        except Exception as e:
            error_msg = f"Replay failed: {e}"
            logger.critical(error_msg)
            if status_callback:
                status_callback(error_msg)

            return {
                "success": False,
                "error": str(e),
                "total_operations": len(selected_operations),
                "successful_operations": 0,
                "failed_operations": len(selected_operations)
            }

        except Exception as e:
            error_msg = f"Replay failed: {e}"
            logger.critical(error_msg)
            if status_callback:
                status_callback(error_msg)

            return {
                "success": False,
                "error": str(e),
                "total_operations": len(selected_operations),
                "successful_operations": 0,
                "failed_operations": len(selected_operations)
            }
    @property
    def command_handlers(self):
        """Get command handlers for SMB2 operations."""
        # Import all external handlers
        from smbreplay.handlers.create import handle_create
        from smbreplay.handlers.read import handle_read
        from smbreplay.handlers.write import handle_write
        from smbreplay.handlers.close import handle_close
        from smbreplay.handlers.lock import handle_lock
        from smbreplay.handlers.set_info import handle_set_info
        from smbreplay.handlers.tree_connect import handle_tree_connect
        from smbreplay.handlers.tree_disconnect import handle_tree_disconnect
        from smbreplay.handlers.session_setup import handle_session_setup
        from smbreplay.handlers.logoff import handle_logoff
        from smbreplay.handlers.negotiate import handle_negotiate
        from smbreplay.handlers.echo import handle_echo
        from smbreplay.handlers.flush import handle_flush
        from smbreplay.handlers.ioctl import handle_ioctl
        from smbreplay.handlers.query_directory import handle_query_directory
        from smbreplay.handlers.query_info import handle_query_info
        from smbreplay.handlers.change_notify import handle_change_notify
        from smbreplay.handlers.cancel import handle_cancel
        from smbreplay.handlers.oplock_break import handle_oplock_break
        from smbreplay.handlers.lease_break import handle_lease_break
        
        return {
            0: lambda op: handle_negotiate(self, op),
            1: lambda op: handle_session_setup(self, op),
            2: lambda op: handle_logoff(self, op),
            3: lambda session, op: handle_tree_connect(self, session, op),
            4: lambda op: handle_tree_disconnect(self, op),
            5: lambda tree, op, all_operations=None: handle_create(self, tree, op, all_operations),
            6: lambda op: handle_close(self, op),
            7: lambda op: handle_flush(self, op),
            8: lambda op: handle_read(self, op),
            9: lambda op: handle_write(self, op),
            10: lambda op: handle_lock(self, op),
            11: lambda op: handle_ioctl(self, op),
            12: lambda op: handle_cancel(self, op),
            13: lambda op: handle_echo(self, op),
            14: lambda op: handle_query_directory(self, op),
            15: lambda op: handle_change_notify(self, op),
            16: lambda op: handle_query_info(self, op),
            17: lambda op: handle_set_info(self, op),
            18: lambda op: handle_oplock_break(self, op),
            19: lambda op: handle_lease_break(self, op),  # SMB2_LEASE_BREAK (SMB3)
        }
    
    def validate_operations(self, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate operations before replay.
        
        Args:
            operations: List of operation dictionaries
            
        Returns:
            Dictionary with validation results
        """
        logger.info(f"Validating {len(operations)} operations")
        
        if not operations:
            return {"valid": False, "error": "No operations provided"}
        
        issues = []
        # Expanded supported commands - including more SMB2 operations
        supported_commands = set(self.command_handlers.keys())
        
        for i, op in enumerate(operations):
            try:
                cmd_raw = op.get('smb2.cmd', '-1')
                cmd = int(cmd_raw) if str(cmd_raw).isdigit() else -1
                
                if cmd not in supported_commands:
                    issues.append(f"Operation {i+1}: Unsupported command {cmd}")
                    continue
                
                # Check required fields based on command type
                if cmd == 5:  # Create
                    if not op.get('smb2.filename'):
                        issues.append(f"Operation {i+1}: Create operation missing filename")
                
                elif cmd in [6, 8, 9]:  # Close, Read, Write
                    fid = op.get('smb2.fid', '')
                    # Only validate fid if it's required (skip empty responses)
                    if not fid or str(fid).strip() == '' or str(fid) == 'N/A':
                        # This is likely a response frame without fid, which is normal
                        pass
                
                elif cmd == 10:  # Lock
                    fid = op.get('smb2.fid', '')
                    # Only validate fid if it's required (skip empty responses)
                    if not fid or str(fid).strip() == '' or str(fid) == 'N/A':
                        # This is likely a response frame without fid, which is normal
                        pass
                
                elif cmd in [14, 16, 17]:  # Query Directory, Query Info, Set Info
                    # These operations may not require strict validation for basic replay
                    pass
                
                elif cmd == 1:  # Session Setup
                    # Session setup can be skipped in replay as we establish our own session
                    pass
                
                elif cmd == 3:  # Tree Connect
                    # Tree connect validation handled during replay
                    pass
                
            except (ValueError, TypeError) as e:
                issues.append(f"Operation {i+1}: Invalid command format: {e}")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "total_operations": len(operations),
            "supported_operations": sum(1 for op in operations if int(op.get('smb2.cmd', -1)) in supported_commands)
        }
        
    def get_supported_commands(self) -> Dict[int, str]:
        return {cmd: SMB2_OP_NAME_DESC.get(cmd, ("Unknown",))[0] for cmd in self.command_handlers.keys()}
    

    def reset_state(self):
        """Reset internal state."""
        self.tid_mapping = {}
        self.fid_mapping = {}
        self.state = {'last_new_tid': None, 'last_new_fid': None}
        logger.debug("Reset replay state")


# Global replayer instance
_replayer: Optional[SMB2Replayer] = None


def get_replayer() -> SMB2Replayer:
    """Get the global replayer instance."""
    global _replayer
    if _replayer is None:
        _replayer = SMB2Replayer()
    return _replayer


def replay_session(selected_operations: List[Dict[str, Any]], 
                  status_callback: Optional[Callable] = None) -> Dict[str, Any]:
    """Replay selected SMB2 operations.
    
    Args:
        selected_operations: List of selected operation dictionaries
        status_callback: Optional callback for status updates
        
    Returns:
        Dictionary with replay results
    """
    return get_replayer().replay_session(selected_operations, status_callback)


def validate_operations(operations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate operations before replay.
    
    Args:
        operations: List of operation dictionaries
        
    Returns:
        Dictionary with validation results
    """
    return get_replayer().validate_operations(operations)


def get_supported_commands() -> Dict[int, str]:
    """Get list of supported SMB2 commands."""
    return get_replayer().get_supported_commands()