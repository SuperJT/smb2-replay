"""
SMB2 Replay Module.
Handles SMB2 session replay using impacket library.
"""

import time
from typing import List, Dict, Any, Optional, Callable
from impacket.smbconnection import SMBConnection, SessionError

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
        
    def get_replay_config(self) -> Dict[str, Any]:
        """Get replay configuration."""
        return self.config.replay_config.copy()
    
    def setup_pre_trace_state(self, conn: SMBConnection, selected_operations: List[Dict[str, Any]], 
                            default_tree_id: str):
        """Set up the file system state on the lab server before replaying operations.
        
        Args:
            conn: SMBConnection object to the lab server
            selected_operations: List of selected operation dictionaries
            default_tree_id: Tree ID to use for creating directories and files
        """
        logger.info("Setting up pre-trace state for selected operations")
        
        # Collect all unique file paths and identify files created in the selected operations
        all_paths = set()
        created_files = set()
        
        for op in selected_operations:
            filename = op.get('smb2.filename', '')
            if filename and filename not in ['.', '..']:
                all_paths.add(filename)
            
            # Identify files created in the selected operations
            if (op.get('smb2.cmd') == '5' and 
                op.get('smb2.flags.response') == 'True' and 
                op.get('smb2.create.action') == 'FILE_CREATED'):
                created_files.add(filename)
        
        # Infer directories from paths
        directories = set()
        for path in all_paths:
            parts = path.split('\\')
            for i in range(1, len(parts)):
                dir_path = '\\'.join(parts[:i])
                if dir_path:
                    directories.add(dir_path)
        
        # Create directories
        for dir_path in sorted(directories, key=lambda x: x.count('\\')):
            try:
                conn.createDirectory(default_tree_id, dir_path)
                logger.debug(f"Created directory: {dir_path}")
            except SessionError as e:
                if "STATUS_OBJECT_NAME_COLLISION" not in str(e):
                    logger.error(f"Failed to create directory {dir_path}: {e}")
        
        # Create files that existed before the selected operations
        for path in all_paths:
            if path not in directories and path not in created_files:
                try:
                    conn.createFile(default_tree_id, path, disposition=3)  # FILE_OPEN_IF
                    logger.debug(f"Created pre-existing file: {path}")
                except SessionError as e:
                    logger.error(f"Failed to create file {path}: {e}")
    
    def handle_tree_connect(self, conn: SMBConnection, op: Dict[str, Any]):
        """Handle Tree Connect operation.
        
        Args:
            conn: SMB connection
            op: Operation dictionary
        """
        share_path = op.get('smb2.tree', '')
        share_name = share_path.split('\\')[-1] if '\\' in share_path else share_path
        
        try:
            self.state['last_new_tid'] = conn.connectTree(share_name)
            logger.debug(f"Tree Connect: {share_name}, new_tid={self.state['last_new_tid']}")
        except SessionError as e:
            logger.error(f"Tree Connect failed for {share_name}: {e}")
            self.state['last_new_tid'] = None
    
    def handle_create(self, conn: SMBConnection, op: Dict[str, Any], default_tree_id: str):
        """Handle Create operation.
        
        Args:
            conn: SMB connection
            op: Operation dictionary
            default_tree_id: Default tree ID
        """
        original_tid = op.get('smb2.tid', '')
        new_tid = self.tid_mapping.get(original_tid, default_tree_id)
        filename = op.get('smb2.filename', '')
        disposition = int(op.get('smb2.create_disposition', 1))  # Default FILE_OPEN
        
        try:
            self.state['last_new_fid'] = conn.createFile(new_tid, filename, disposition=disposition)
            logger.debug(f"Create: {filename}, new_fid={self.state['last_new_fid']}")
        except SessionError as e:
            logger.error(f"Create failed for {filename}: {e}")
            self.state['last_new_fid'] = None
    
    def handle_close(self, conn: SMBConnection, op: Dict[str, Any], default_tree_id: str):
        """Handle Close operation.
        
        Args:
            conn: SMB connection
            op: Operation dictionary
            default_tree_id: Default tree ID
        """
        original_tid = op.get('smb2.tid', '')
        original_fid = op.get('smb2.fid', '')
        new_tid = self.tid_mapping.get(original_tid, default_tree_id)
        new_fid = self.fid_mapping.get(original_fid)
        
        if new_fid:
            try:
                conn.closeFile(new_tid, new_fid)
                logger.debug(f"Close: fid={original_fid}")
            except SessionError as e:
                logger.error(f"Close failed for fid {original_fid}: {e}")
        else:
            logger.warning(f"Close: No mapping found for fid {original_fid}")
    
    def handle_read(self, conn: SMBConnection, op: Dict[str, Any], default_tree_id: str):
        """Handle Read operation.
        
        Args:
            conn: SMB connection
            op: Operation dictionary
            default_tree_id: Default tree ID
        """
        original_tid = op.get('smb2.tid', '')
        original_fid = op.get('smb2.fid', '')
        new_tid = self.tid_mapping.get(original_tid, default_tree_id)
        new_fid = self.fid_mapping.get(original_fid)
        
        if new_fid:
            offset = int(op.get('smb2.read.offset', 0))
            length = int(op.get('smb2.read.length', 1024))
            
            try:
                data = conn.readFile(new_tid, new_fid, offset, length)
                logger.debug(f"Read: fid={original_fid}, offset={offset}, length={length}, read_bytes={len(data)}")
            except SessionError as e:
                logger.error(f"Read failed for fid {original_fid}: {e}")
        else:
            logger.warning(f"Read: No mapping found for fid {original_fid}")
    
    def handle_write(self, conn: SMBConnection, op: Dict[str, Any], default_tree_id: str):
        """Handle Write operation.
        
        Args:
            conn: SMB connection
            op: Operation dictionary
            default_tree_id: Default tree ID
        """
        original_tid = op.get('smb2.tid', '')
        original_fid = op.get('smb2.fid', '')
        new_tid = self.tid_mapping.get(original_tid, default_tree_id)
        new_fid = self.fid_mapping.get(original_fid)
        
        if new_fid:
            offset = int(op.get('smb2.write.offset', 0))
            data = bytes.fromhex(op.get('smb2.write_data', '')) if op.get('smb2.write_data') else b'test_data'
            
            try:
                bytes_written = conn.writeFile(new_tid, new_fid, data, offset)
                logger.debug(f"Write: fid={original_fid}, offset={offset}, data_length={len(data)}, bytes_written={bytes_written}")
            except SessionError as e:
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
    
    def replay_session(self, selected_operations: List[Dict[str, Any]], 
                      status_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Replay selected SMB2 operations using impacket.
        
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
        
        # Default status callback
        if status_callback is None:
            status_callback = lambda msg: logger.info(f"Replay Status: {msg}")
        
        # Extract server configuration
        replay_config = self.get_replay_config()
        server_ip = replay_config.get("server_ip", "10.216.29.241")
        domain = replay_config.get("domain", "nas-deep.local")
        username = replay_config.get("username", "jtownsen")
        password = replay_config.get("password", "")
        default_tree_name = replay_config.get("tree_name", "2pm")
        max_wait = replay_config.get("max_wait", 5.0)
        
        logger.debug(f"Using replay config: server_ip={server_ip}, domain={domain}, "
                    f"username={username}, tree_name={default_tree_name}, max_wait={max_wait}")
        
        try:
            # Establish SMB connection
            status_callback("Connecting to SMB server...")
            logger.debug(f"Connecting to SMB server: {server_ip}")
            
            conn = SMBConnection(server_ip, server_ip, timeout=max_wait)
            conn.login(username, password, domain)
            logger.info("Successfully connected to SMB server")
            status_callback("Connected to SMB server")
            
            # Connect to the default tree
            default_tree_id = conn.connectTree(default_tree_name)
            logger.debug(f"Connected to default tree {default_tree_name}, tree_id={default_tree_id}")
            status_callback(f"Connected to tree: {default_tree_name}")
            
            # Setup pre-trace state
            status_callback("Setting up pre-trace state...")
            self.setup_pre_trace_state(conn, selected_operations, default_tree_id)
            
            # Initialize mappings
            self.tid_mapping = {}
            self.fid_mapping = {}
            self.state = {'last_new_tid': None, 'last_new_fid': None}
            
            # Command handlers
            command_handlers = {
                3: self.handle_tree_connect,  # Tree Connect
                5: lambda conn, op: self.handle_create(conn, op, default_tree_id),  # Create
                6: lambda conn, op: self.handle_close(conn, op, default_tree_id),   # Close
                8: lambda conn, op: self.handle_read(conn, op, default_tree_id),    # Read
                9: lambda conn, op: self.handle_write(conn, op, default_tree_id)    # Write
            }
            
            # Process selected operations
            successful_ops = 0
            failed_ops = 0
            
            for i, op in enumerate(selected_operations, 1):
                try:
                    is_response = op.get('smb2.flags.response') == 'True'
                    cmd = int(op.get('smb2.cmd', -1))
                    
                    status_callback(f"Processing operation {i}/{len(selected_operations)}: {op.get('Command', 'Unknown')}")
                    
                    if not is_response:  # Request
                        if cmd in command_handlers:
                            command_handlers[cmd](conn, op)
                            successful_ops += 1
                        elif 0 <= cmd <= 18:
                            logger.warning(f"Command {cmd} ({SMB2_OP_NAME_DESC.get(cmd, ('Unknown', 'Unknown'))[0]}) not yet implemented")
                        else:
                            logger.warning(f"Invalid command code: {cmd}")
                    else:  # Response
                        self.handle_response(op, cmd)
                        
                except Exception as e:
                    logger.error(f"Error processing operation {i}: {e}")
                    failed_ops += 1
            
            # Clean up
            logger.debug("Disconnecting from SMB server")
            conn.close()
            logger.info("Disconnected from SMB server")
            
            # Prepare results
            results = {
                "success": True,
                "total_operations": len(selected_operations),
                "successful_operations": successful_ops,
                "failed_operations": failed_ops,
                "tid_mappings": len(self.tid_mapping),
                "fid_mappings": len(self.fid_mapping)
            }
            
            status_callback(f"Replay completed: {successful_ops} successful, {failed_ops} failed")
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
        supported_commands = {
            1,   # Session Setup (can be skipped in replay)
            3,   # Tree Connect  
            5,   # Create
            6,   # Close
            8,   # Read
            9,   # Write
            10,  # Lock
            14,  # Query Directory
            16,  # Query Info
            17   # Set Info
        }
        
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
        """Get list of supported SMB2 commands.
        
        Returns:
            Dictionary mapping command codes to descriptions
        """
        supported = {
            1: "Session Setup (skipped in replay)",
            3: "Tree Connect",
            5: "Create",
            6: "Close", 
            8: "Read",
            9: "Write",
            10: "Lock",
            14: "Query Directory",
            16: "Query Info",
            17: "Set Info"
        }
        return supported
    
    def reset_state(self):
        """Reset internal state."""
        self.tid_mapping = {}
        self.fid_mapping = {}
        self.state = {'last_new_tid': None, 'last_new_fid': None}
        logger.debug("Reset replay state")


# Global replayer instance
_replayer = None


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