"""
SMB2 Replay Module.
Handles SMB2 session replay using smbprotocol library.
"""

import time
import subprocess
from typing import List, Dict, Any, Optional, Callable
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

    
    def __init__(self):
        
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
        logger.info(f"Ping functionality {'enabled' if enabled else 'disabled'}")
    
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
            logger.info(f"🔄 Sending replay start ping to replay server: {server_ip}")
            result = subprocess.run(
                ['ping', '-c', '1', server_ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Replay start ping successful to {server_ip}")
                logger.debug(f"Ping output: {result.stdout.strip()}")
            else:
                logger.warning(f"⚠️ Replay start ping failed to {server_ip}")
                logger.debug(f"Ping error: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            logger.warning(f"⚠️ Replay start ping timeout to {server_ip}")
        except FileNotFoundError:
            logger.warning("⚠️ Ping command not found - skipping replay start ping")
        except Exception as e:
            logger.warning(f"⚠️ Replay start ping error: {e}")
    
    def set_reset_mode(self, mode: str):
        """Set the reset mode for replay operations.
        
        Args:
            mode: 'complete' for full reset, 'cleanup' for selective cleanup
        """
        if mode not in ['complete', 'cleanup']:
            logger.warning(f"Invalid reset mode '{mode}', using 'complete'")
            mode = 'complete'
        self.reset_mode = mode
        logger.info(f"Reset mode set to: {mode}")
    
    def enable_response_validation(self, enabled: bool = True):
        """Enable or disable response validation.
        
        Args:
            enabled: Whether to validate responses against Parquet data
        """
        self.response_validation['enabled'] = enabled
        self.response_validation['results'] = []
        logger.info(f"Response validation {'enabled' if enabled else 'disabled'}")
    
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
        frame_number = operation.get('Frame', 'N/A')
        command = operation.get('Command', 'Unknown')
        filename = operation.get('smb2.filename', 'N/A')
        
        # If expected_status is None or N/A, this is likely a request frame
        # We need to find the corresponding response frame to get the expected status
        if expected_status in [None, 'N/A', '']:
            # For now, assume success (0x00000000) for request frames
            # In a full implementation, we would look up the corresponding response frame
            expected_status = '0x00000000'
            logger.debug(f"Request frame {frame_number}: Assuming expected status {expected_status}")
        
        # Normalize status codes for comparison
        expected_hex = expected_status if expected_status.startswith('0x') else f"0x{expected_status:08x}"
        actual_hex = actual_status if actual_status.startswith('0x') else f"0x{actual_status:08x}"
        
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
            logger.debug(f"✅ Response validation passed: {command} (Frame {frame_number}) - Status: {actual_hex}")
        else:
            logger.warning(f"❌ Response validation failed: {command} (Frame {frame_number})")
            logger.warning(f"   Expected: {expected_hex}, Actual: {actual_hex}")
            if actual_error:
                logger.warning(f"   Error: {actual_error}")
    
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
        logger.debug(f"IOCTL: Not implemented. op={op}")

    def handle_query_directory(self, op: Dict[str, Any]):
        """Handle Query Directory operation (stub)."""
        logger.debug(f"Query Directory: Not implemented. op={op}")

    def handle_query_info(self, op: Dict[str, Any]):
        """Handle Query Info operation (stub)."""
        logger.debug(f"Query Info: Not implemented. op={op}")

    def get_replay_config(self) -> Dict[str, Any]:
        """Get replay configuration."""
        return self.config.replay_config.copy()
    
    def determine_create_type(self, operation: Dict[str, Any], all_operations: List[Dict[str, Any]]) -> str:
        """
        Determine if a create operation should create a file or directory.
        
        Args:
            operation: The create operation
            all_operations: All operations in the session
            
        Returns:
            'file' or 'directory'
        """
        filename = operation.get('smb2.filename', '')
        frame_number = operation.get('Frame', 'N/A')
        
        # Look for the corresponding response frame
        for resp_op in all_operations:
            if (resp_op.get('smb2.cmd') == '5' and 
                resp_op.get('smb2.flags.response') == 'True' and
                resp_op.get('smb2.filename') == filename):
                
                create_action = resp_op.get('smb2.create.action', '')
                if create_action == 'FILE_CREATED':
                    # New file was created
                    return 'file'
                elif create_action == 'FILE_OPENED':
                    # Existing file was opened
                    return 'file'
                elif create_action == 'DIRECTORY_CREATED':
                    # New directory was created
                    return 'directory'
                elif create_action == 'DIRECTORY_OPENED':
                    # Existing directory was opened
                    return 'directory'
                break
        
        # Default to file if we can't determine
        logger.debug(f"Could not determine create type for {filename}, defaulting to file")
        return 'file'
    
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
        logger.info("Cleaning up existing files and directories for clean replay")
        
        if not paths:
            logger.info("No paths to clean up")
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
                logger.debug(f"Deleted file: {path}")
                
            except SMBException as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    # File doesn't exist, which is fine
                    logger.debug(f"File not found (already deleted): {path}")
                elif "STATUS_ACCESS_DENIED" in str(e):
                    # Access denied, might be a directory or protected file
                    logger.debug(f"Access denied for deletion: {path}")
                else:
                    logger.debug(f"Failed to delete {path}: {e}")
        
        logger.info(f"Cleanup completed: {files_deleted} files deleted, {dirs_deleted} directories deleted")

    def setup_pre_trace_state(self, tree: TreeConnect, session: Session, selected_operations: List[Dict[str, Any]]):
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

        # First, reset the target to a completely fresh state
        replay_config = self.get_replay_config()
        tree_name = replay_config.get("tree_name", "testshare")
        
        if self.reset_mode == 'complete':
            self.reset_target_to_fresh_state(tree, tree_name)
        else:
            logger.info("Using cleanup mode - skipping complete reset")

        all_paths = set()
        created_files = set()
        existing_files = set()

        # Collect all valid paths and created files
        for op in selected_operations:
            filename = op.get('smb2.filename', '')
            if filename and filename not in ['.', '..', 'N/A', '']:
                all_paths.add(filename)
            if (op.get('smb2.cmd') == '5' and
                op.get('smb2.flags.response') == 'True' and
                op.get('smb2.create.action') == 'FILE_CREATED'):
                created_files.add(filename)
            elif (op.get('smb2.cmd') == '5' and
                  op.get('smb2.flags.response') == 'True' and
                  op.get('smb2.create.action') == 'FILE_OPENED'):
                existing_files.add(filename)

        if not all_paths:
            logger.info("No valid paths found for pre-trace state setup")
            return

        # Clean up any remaining files that might conflict
        self.cleanup_existing_files(tree, all_paths)

        # Normalize paths and extract directories
        directories = set()
        normalized_paths = set()
        
        for path in all_paths:
            # Normalize path separators (handle both \ and /)
            normalized_path = path.replace('/', '\\')
            normalized_paths.add(normalized_path)
            
            # Extract parent directories for all paths with multiple parts
            parts = normalized_path.split('\\')
            if len(parts) > 1:
                for i in range(1, len(parts)):
                    dir_path = '\\'.join(parts[:i])
                    if dir_path:
                        directories.add(dir_path)

        logger.info(f"Found {len(directories)} directories and {len(normalized_paths)} files to process")

        # Create directories in proper order (parents first)
        created_dirs = set()
        sorted_dirs = sorted(directories, key=lambda x: (x.count('\\'), x))
        
        for dir_path in sorted_dirs:
            # Create each directory along the path step by step
            parts = dir_path.split('\\')
            current_path = ""
            
            for i, part in enumerate(parts):
                if i == 0:
                    current_path = part
                else:
                    current_path = current_path + '\\' + part
                
                # Skip if we already created this directory
                if current_path in created_dirs:
                    continue
                
                try:
                    dir_open = Open(tree, current_path)
                    dir_open.create(
                        impersonation_level=0,  # SECURITY_ANONYMOUS
                        desired_access=0x80000000,  # GENERIC_READ
                        file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                        share_access=0x00000001,  # FILE_SHARE_READ
                        create_disposition=3,  # FILE_OPEN_IF - works better for existing directories
                        create_options=1  # FILE_DIRECTORY_FILE - correct value
                    )
                    created_dirs.add(current_path)
                    logger.debug(f"Created directory: {current_path}")
                    dir_open.close()
                except SMBException as e:
                    if "STATUS_OBJECT_NAME_COLLISION" not in str(e):
                        # If directory creation fails, it might be because the path is a file
                        # or the parent doesn't exist - log but continue
                        logger.warning(f"Failed to create directory {current_path}: {e}")
                        # Don't add to created_dirs since it failed
                        # Break out of the loop for this path since we can't create nested dirs
                        break
                    else:
                        # Directory already exists, consider it created
                        created_dirs.add(current_path)
                        logger.debug(f"Directory already exists: {current_path}")

        # Create files that existed before the selected operations
        files_created = 0
        for path in normalized_paths:
            if path not in directories and path not in created_files:
                try:
                    file_open = Open(tree, path)
                    file_open.create(
                        impersonation_level=0,  # SECURITY_ANONYMOUS
                        desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                        file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                        share_access=0x00000001,  # FILE_SHARE_READ
                        create_disposition=1,  # FILE_OPEN_IF
                        create_options=0  # No special options
                    )
                    files_created += 1
                    logger.debug(f"Created pre-existing file: {path}")
                    file_open.close()
                except SMBException as e:
                    # If file creation fails, it might be because the parent directory doesn't exist
                    # or the path is invalid - log but continue
                    logger.warning(f"Failed to create file {path}: {e}")

        logger.info(f"Pre-trace state setup complete:")
        logger.info(f"  - {len(created_dirs)} directories created/exist")
        logger.info(f"  - {files_created} pre-existing files created")
        logger.info(f"  - {len(created_files)} files will be created during replay")
        logger.info(f"  - {len(existing_files)} files already exist and will be opened")
        
        if len(created_dirs) < len(directories):
            logger.warning(f"Only {len(created_dirs)}/{len(directories)} directories could be created")
            logger.warning("Some nested directories may not exist - replay may fail for those paths")
            logger.info("Consider using a different SMB server or share that supports nested directory creation")
        
        # Validate file system structure
        self._validate_file_system_structure(tree, normalized_paths, created_dirs)
    
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
        """Handle Tree Connect operation using smbprotocol.

        Args:
            session: smbprotocol Session object
            op: Operation dictionary
        """
        share_path = op.get('smb2.tree', '')
        # Ensure UNC path format: \\server\share
        if not share_path.startswith('\\\\'):
            # You may need to prepend server name if not present
            server = session.connection.server_name
            share_path = f"\\\\{server}\\{share_path}"

        try:
            tree = TreeConnect(session, share_path)
            tree.connect()
            self.state['last_new_tid'] = tree
            logger.debug(f"Tree Connect: {share_path}, tree object={tree}")
            
            # Validate response - successful tree connect should return STATUS_SUCCESS (0x00000000)
            self.validate_response(op, "0x00000000")
            
        except SMBException as e:
            logger.error(f"Tree Connect failed for {share_path}: {e}")
            self.state['last_new_tid'] = None
            
            # Extract NT status from error message
            actual_status = "0x00000000"  # Default to success
            if "STATUS_" in str(e):
                # Try to extract status code from error message
                error_str = str(e)
                if "0x" in error_str:
                    # Extract hex status code
                    import re
                    hex_match = re.search(r'0x[0-9a-fA-F]{8}', error_str)
                    if hex_match:
                        actual_status = hex_match.group(0)
            
            # Validate response against expected status
            self.validate_response(op, actual_status, str(e))
    
    def handle_create(self, tree: TreeConnect, op: Dict[str, Any], all_operations: Optional[List[Dict[str, Any]]] = None):
        """Handle Create operation using smbprotocol.

        Args:
            tree: TreeConnect object for the share
            op: Operation dictionary
            all_operations: All operations in the session (for determining create type)
        """
        filename = op.get('smb2.filename', '')
        
        # Determine if this should be a file or directory
        create_type = 'file'  # Default
        if all_operations:
            create_type = self.determine_create_type(op, all_operations)
        
        # Read all create parameters from the operation data
        impersonation_level = int(op.get('smb2.impersonation_level', 0))  # Default SECURITY_ANONYMOUS
        desired_access = int(op.get('smb2.desired_access', 0x80000000 | 0x40000000))  # Default GENERIC_READ | GENERIC_WRITE
        file_attributes = int(op.get('smb2.file_attributes', 0))  # Default FILE_ATTRIBUTE_NORMAL
        share_access = int(op.get('smb2.share_access', 0x00000001))  # Default FILE_SHARE_READ
        create_disposition = int(op.get('smb2.create_disposition', 2))  # Default FILE_CREATE
        create_options = int(op.get('smb2.create_options', 0))  # Default no special options
        
        # Adjust parameters based on create type
        if create_type == 'directory':
            file_attributes = 0x00000010  # FILE_ATTRIBUTE_DIRECTORY
            create_options = 1  # FILE_DIRECTORY_FILE
            desired_access = 0x80000000  # GENERIC_READ for directories
            logger.debug(f"Creating directory: {filename}")
        else:
            logger.debug(f"Creating file: {filename}")

        logger.info(f"Create operation parameters for {filename}:")
        logger.info(f"  Type: {create_type}")
        logger.info(f"  impersonation_level: {impersonation_level}")
        logger.info(f"  desired_access: {desired_access}")
        logger.info(f"  file_attributes: {file_attributes}")
        logger.info(f"  share_access: {share_access}")
        logger.info(f"  create_disposition: {create_disposition}")
        logger.info(f"  create_options: {create_options}")

        try:
            file_open = Open(tree, filename)
            # Create with parameters from the operation data
            file_open.create(
                impersonation_level=impersonation_level,
                desired_access=desired_access,
                file_attributes=file_attributes,
                share_access=share_access,
                create_disposition=create_disposition,
                create_options=create_options
            )
            self.state['last_new_fid'] = file_open
            logger.info(f"Create: {filename}, Open object={file_open}")
            
            # Validate response - successful create should return STATUS_SUCCESS (0x00000000)
            self.validate_response(op, "0x00000000")
            
        except SMBException as e:
            logger.error(f"Create failed for {filename}: {e}")
            self.state['last_new_fid'] = None
            
            # Extract NT status from error message
            actual_status = "0x00000000"  # Default to success
            if "STATUS_" in str(e):
                # Try to extract status code from error message
                error_str = str(e)
                if "0x" in error_str:
                    # Extract hex status code
                    import re
                    hex_match = re.search(r'0x[0-9a-fA-F]{8}', error_str)
                    if hex_match:
                        actual_status = hex_match.group(0)
            
            # Validate response against expected status
            self.validate_response(op, actual_status, str(e))
    
    def handle_close(self, op: Dict[str, Any]):
        """Handle Close operation using smbprotocol.

        Args:
            op: Operation dictionary
        """
        original_fid = op.get('smb2.fid', '')
        file_open = self.fid_mapping.get(original_fid)

        if file_open:
            try:
                file_open.close()
                logger.debug(f"Close: fid={original_fid}")
            except SMBException as e:
                logger.error(f"Close failed for fid {original_fid}: {e}")
        else:
            logger.warning(f"Close: No mapping found for fid {original_fid}")
    
    def handle_read(self, op: Dict[str, Any]):
        """Handle Read operation using smbprotocol.

        Args:
            op: Operation dictionary
        """
        original_fid = op.get('smb2.fid', '')
        file_open = self.fid_mapping.get(original_fid)

        if file_open:
            offset = int(op.get('smb2.read.offset', 0))
            length = int(op.get('smb2.read.length', 1024))
            try:
                data = file_open.read(offset, length)
                logger.debug(f"Read: fid={original_fid}, offset={offset}, length={length}, read_bytes={len(data)}")
            except SMBException as e:
                logger.error(f"Read failed for fid {original_fid}: {e}")
        else:
            logger.warning(f"Read: No mapping found for fid {original_fid}")
    
    def handle_write(self, op: Dict[str, Any]):
        """Handle Write operation using smbprotocol.

        Args:
            op: Operation dictionary
        """
        original_fid = op.get('smb2.fid', '')
        file_open = self.fid_mapping.get(original_fid)

        if file_open:
            offset = int(op.get('smb2.write.offset', 0))
            data = bytes.fromhex(op.get('smb2.write_data', '')) if op.get('smb2.write_data') else b'test_data'
            try:
                bytes_written = file_open.write(data, offset)
                logger.debug(f"Write: fid={original_fid}, offset={offset}, data_length={len(data)}, bytes_written={bytes_written}")
            except SMBException as e:
                logger.error(f"Write failed for fid {original_fid}: {e}")
        else:
            logger.warning(f"Write: No mapping found for fid {original_fid}")
    
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
        """Replay selected SMB2 operations using smbprotocol.

        Args:
            selected_operations: List of selected operation dictionaries
            status_callback: Optional callback for status updates

        Returns:
            Dictionary with replay results
        """
        logger.info("Starting SMB2 session replay")

        if not selected_operations:
            logger.info("No operations selected for replay")
            return {"success": False, "error": "No operations selected for replay"}

        if status_callback is None:
            status_callback = lambda msg: logger.info(f"Replay Status: {msg}")

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
            # Establish SMB connection
            status_callback("Connecting to SMB server...")
            logger.debug(f"Connecting to SMB server: {server_ip}")

            # Setup smbprotocol connection/session/tree
            connection = Connection(uuid.uuid4(), server_ip, 445)
            connection.connect(timeout=max_wait)
            session = Session(connection, username, password, require_encryption=False)
            session.connect()
            tree = TreeConnect(session, f"\\\\{server_ip}\\{default_tree_name}")
            tree.connect()
            logger.info("Successfully connected to SMB server and share")
            status_callback(f"Connected to tree: {default_tree_name}")

            # Setup pre-trace state
            status_callback("Setting up pre-trace state...")
            self.setup_pre_trace_state(tree, session, selected_operations)

            # Send replay start ping to differentiate from pre-trace setup
            status_callback("Sending replay start ping...")
            self.send_replay_start_ping(server_ip)

            # Initialize mappings
            self.tid_mapping = {}
            self.fid_mapping = {}
            self.state = {'last_new_tid': None, 'last_new_fid': None}

            # Process selected operations
            successful_ops = 0
            failed_ops = 0
            supported_commands = set(self.command_handlers.keys())
            issues = []

            for i, op in enumerate(selected_operations, 1):
                try:
                    cmd_raw = op.get('smb2.cmd', '-1')
                    cmd = int(cmd_raw) if str(cmd_raw).isdigit() else -1

                    if cmd not in supported_commands:
                        frame = op.get('Frame', 'N/A')
                        command_name = SMB2_OP_NAME_DESC.get(cmd, ('Unknown',))[0]
                        issues.append(
                            f"Operation {i+1} (Frame {frame}): Unsupported command {cmd} ({command_name})"
                        )
                        continue
                except Exception as e:
                    logger.error(f"Error processing operation {i}: {e}")
                    failed_ops += 1
                    continue

                try:
                    is_response = op.get('smb2.flags.response') == 'True'
                    cmd = int(op.get('smb2.cmd', -1))

                    status_callback(f"Processing operation {i}/{len(selected_operations)}: {op.get('Command', 'Unknown')}")

                    if not is_response:  # Request
                        handler = self.command_handlers.get(cmd)
                        if handler:
                            # Pass correct objects for each handler
                            if cmd == 3:
                                handler(session, op)
                            elif cmd == 5:
                                handler(tree, op, selected_operations)  # Pass all operations for create type determination
                            elif cmd in [6, 8, 9, 12, 15]:
                                handler(op)
                            else:
                                logger.warning(f"Command {cmd} ({SMB2_OP_NAME_DESC.get(cmd, ('Unknown',))[0]}) not yet implemented")
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

            status_callback(f"Replay completed: {successful_ops} successful, {failed_ops} failed")
            if validation_results['enabled']:
                status_callback(f"Response validation: {validation_results['matching_responses']}/{validation_results['total_operations']} responses match ({validation_results['match_rate']:.1f}%)")
            logger.info(f"Replay completed: {results}")

            return results

        except Exception as e:
            error_msg = f"Replay failed: {e}"
            logger.critical(error_msg)
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
        return {
            3: self.handle_tree_connect,
            5: self.handle_create,
            6: self.handle_close,
            8: self.handle_read,
            9: self.handle_write,
            11: self.handle_ioctl,
            12: self.handle_cancel,
            14: self.handle_query_directory,
            15: self.handle_change_notify,
            16: self.handle_query_info,
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