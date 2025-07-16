"""
Session Management Module.
Handles session loading, filtering, and operations management for SMB2 analysis.
"""

import os
import time
import uuid
from typing import List, Dict, Optional, Any
import pandas as pd
import pyarrow.parquet as pq

from .config import get_config, get_logger, get_traces_folder
from .constants import (
    FIELD_MAPPINGS, shorten_path, normalize_path, get_tree_name_mapping,
    SMB2_OP_NAME_DESC
)
from .tshark_processor import create_session_directory

logger = get_logger()


class SessionManager:
    """Manages SMB2 sessions and operations."""
    
    def __init__(self):
        self.operations = []
        self.session_frames = None
        self.execution_id = str(uuid.uuid4())
        
    def load_capture_path(self) -> Optional[str]:
        """Load capture path from config or environment."""
        logger.info("Loading capture path from configuration")
        
        config = get_config()
        capture = config.get_capture_path()
        
        if capture and os.path.exists(capture):
            logger.info(f"Loaded capture path: {capture}")
            return capture
        
        logger.warning("No valid capture path found in configuration")
        return None
    
    def get_output_directory(self, capture_path: str) -> Optional[str]:
        """Derive output directory from capture path.
        
        Args:
            capture_path: Path to the capture file
            
        Returns:
            Output directory path or None if invalid
        """
        logger.info(f"Deriving output directory for capture: {capture_path}")
        
        if not capture_path:
            logger.warning("No capture file provided")
            return None
        
        try:
            capture_path = os.path.normpath(capture_path)
            
            # Extract case number from capture path
            case_number = "local_case"  # Default for local development
            parts = capture_path.split(os.sep)
            if 'cases' in parts:
                cases_index = parts.index('cases')
                if cases_index + 1 < len(parts):
                    case_number = parts[cases_index + 1]
            
            trace_name = os.path.basename(capture_path).split('.')[0]
            
            # Use create_session_directory from tshark_processor
            output_dir = create_session_directory(case_number, trace_name)
            
            # Verify directory exists and is writable
            if not os.path.exists(output_dir):
                logger.error(f"Directory {output_dir} does not exist")
                return None
            
            if not os.access(output_dir, os.W_OK):
                logger.error(f"Directory {output_dir} is not writable")
                return None
            
            logger.info(f"Output directory: {output_dir}")
            return output_dir
            
        except Exception as e:
            logger.error(f"Error deriving output directory: {e}")
            return None
    
    def list_session_files(self, output_dir: str) -> List[str]:
        """List session Parquet files in the output directory.
        
        Args:
            output_dir: Directory containing session files
            
        Returns:
            List of session file names
        """
        logger.info(f"Listing session files in {output_dir}")
        
        if not output_dir or not os.path.exists(output_dir):
            logger.warning(f"Invalid or missing output directory: {output_dir}")
            return []
        
        try:
            files = os.listdir(output_dir)
            session_files = [f for f in files if f.startswith('smb2_session_') and f.endswith('.parquet')]
            
            # Normalize to lowercase and remove duplicates
            normalized_files = list(dict.fromkeys(f.lower() for f in session_files))
            
            if not normalized_files:
                logger.warning(f"No session files found in {output_dir}")
            else:
                logger.info(f"Found {len(normalized_files)} unique session files")
                logger.debug(f"Session files: {', '.join(normalized_files[:5])}...")
            
            return normalized_files
            
        except Exception as e:
            logger.error(f"Error listing session files: {e}")
            return []
    
    def load_and_summarize_session(self, capture_path: str, session_file: str) -> tuple:
        """Load a session file and return field options and file options.
        
        Args:
            capture_path: Path to the capture file
            session_file: Name of the session file
            
        Returns:
            Tuple of (session_frames, field_options, file_options, selected_fields)
        """
        logger.info(f"Loading session file: {session_file}")
        
        output_dir = self.get_output_directory(capture_path)
        if not output_dir:
            logger.warning("Invalid output directory")
            return None, [], [], []
        
        session_path = os.path.join(output_dir, session_file)
        if not os.path.exists(session_path):
            logger.warning(f"Session file not found: {session_path}")
            return None, [], [], []
        
        try:
            self.session_frames = pq.read_table(session_path).to_pandas()
            logger.info(f"Loaded session {session_file} with {len(self.session_frames)} frames")
            
        except Exception as e:
            logger.error(f"Error loading session file: {e}")
            return None, [], [], []
        
        if self.session_frames.empty:
            logger.warning(f"No frames found in session {session_file}")
            return None, [], [], []
        
        # Get field options
        all_fields = sorted([col for col in self.session_frames.columns if col.startswith('smb2.')])
        volatile_fields = ["smb2.time", "smb2.frame.time"]
        field_options = [f for f in all_fields if f not in volatile_fields]
        
        # Default selected fields
        default_fields = ['smb2.nt_status', 'smb2.create.action']
        selected_fields = [f for f in default_fields if f in field_options]
        
        # Get file options
        unique_files = sorted(set(self.session_frames.get('smb2.filename', pd.Series([])).dropna()) - {'N/A', ''})
        file_options = unique_files
        
        logger.debug(f"Field options: {len(field_options)} fields available")
        logger.debug(f"File options: {len(file_options)} files available")
        
        return self.session_frames, field_options, file_options, selected_fields
    
    def update_operations(self, capture_path: str, session_file: str, 
                         selected_file: Optional[str] = None, 
                         selected_fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Prepare operations data based on selected file and fields.
        
        Args:
            capture_path: Path to the capture file
            session_file: Name of the session file
            selected_file: Optional file filter
            selected_fields: Optional list of fields to include
            
        Returns:
            List of operation dictionaries
        """
        self.operations.clear()
        logger.info(f"Preparing operations for session: {session_file}, file: {selected_file}")
        
        # Load session if not already loaded
        if self.session_frames is None or self.session_frames.empty:
            self.session_frames, _, _, _ = self.load_and_summarize_session(capture_path, session_file)
            if self.session_frames is None or self.session_frames.empty:
                logger.warning(f"Failed to load session data for {session_file}")
                return []
        
        # Default selected fields
        if selected_fields is None:
            selected_fields = ['smb2.nt_status', 'smb2.create.action']
        
        # Filter invalid fields
        selected_fields = [f for f in selected_fields if f in self.session_frames.columns]
        
        # Apply field mappings for normalization
        filtered_frames = self.session_frames.copy()
        
        # Apply field mappings
        for field in FIELD_MAPPINGS:
            if field in filtered_frames.columns:
                mapping = FIELD_MAPPINGS[field]["mapping"]
                normalize = FIELD_MAPPINGS[field]["normalize"]
                
                logger.debug(f"Normalizing field: {field}")
                filtered_frames[field] = filtered_frames[field].apply(normalize)
                
                # Handle special fields
                if field in ["smb2.create.action", "smb2.ioctl.function"]:
                    filtered_frames[f"{field}_desc"] = filtered_frames[field].apply(
                        lambda x: mapping.get(str(x), "") if pd.notna(x) and str(x).strip() != "" and str(x) != "None" else ""
                    )
                else:
                    filtered_frames[f"{field}_desc"] = filtered_frames[field].map(mapping).fillna(
                        filtered_frames[field].apply(lambda x: f"Unknown ({x})" if pd.notna(x) else "")
                    )
        
        # Filter frames based on selected file
        if selected_file and selected_file.strip():
            filtered_frames = filtered_frames[
                filtered_frames['smb2.filename'].apply(normalize_path) == normalize_path(selected_file)
            ]
            logger.debug(f"Filtered to {len(filtered_frames)} frames for file: {selected_file}")
        else:
            logger.info("No file filter applied, processing all frames")
        
        if filtered_frames.empty and selected_file:
            logger.warning(f"No operations found for file: {selected_file}")
            return []
        
        # Process frames into operations
        self.operations = self._process_frames_to_operations(filtered_frames, selected_fields)
        
        logger.info(f"Processed {len(self.operations)} operations")
        return self.operations
    
    def _process_frames_to_operations(self, frames: pd.DataFrame, selected_fields: List[str]) -> List[Dict[str, Any]]:
        """Process DataFrame frames into operation dictionaries.
        
        Args:
            frames: DataFrame with SMB2 frames
            selected_fields: List of fields to include
            
        Returns:
            List of operation dictionaries
        """
        operations = []
        start_time = time.time()
        total_frames = len(frames)
        
        # Get tree name mapping
        tree_mapping = get_tree_name_mapping(frames)
        logger.debug(f"Tree mapping: {tree_mapping}")
        
        mandatory_fields = ['frame.number', 'smb2.cmd', 'smb2.filename', 'smb2.nt_status', 'smb2.flags.response']
        
        def normalize_field(field_str):
            """Normalize field values."""
            if pd.isna(field_str) or not field_str or field_str.strip() == '':
                return "N/A"
            return field_str.split(',')[0].strip()
        
        for idx, row in frames.iterrows():
            if idx % 10000 == 0 and idx > 0:
                logger.debug(f"Processing frame {idx}/{total_frames}")
            
            # Normalize basic fields
            filename = normalize_field(row.get('smb2.filename', 'N/A'))
            tid = normalize_field(row.get('smb2.tid', 'N/A'))
            path = shorten_path(filename) if filename != "N/A" else "N/A"
            
            # Get tree name from mapping - normalize tid for consistent lookup
            tree_name = tree_mapping.get(str(tid), tid) if tid != 'N/A' else 'N/A'
            
            # Use mapped and normalized fields
            status_display = row.get('smb2.nt_status_desc', 'N/A')
            cmd = row.get('smb2.cmd', '-1')
            is_response = row.get('smb2.flags.response', 'False') == 'True'
            op_name = row.get('smb2.cmd_desc', 'Unknown')
            
            # Handle status description
            status_desc = status_display.split('(')[0].strip() if status_display != 'N/A' else 'Not applicable'
            
            # Create operation dictionary
            op = {
                'Frame': row.get('frame.number', 'N/A'),
                'Command': op_name,
                'Path': path,
                'Status': status_display,
                'StatusDesc': status_desc,
                'Tree': tree_name,
                'orig_idx': idx
            }
            
            # Add selected fields
            for field in selected_fields:
                if field not in mandatory_fields:
                    # Special handling for meaningful fields only
                    if field in ["smb2.create.action", "smb2.ioctl.function"]:
                        value = row.get(f"{field}_desc", row.get(field, ""))
                        if value and str(value).strip() != "" and str(value) != "N/A" and not str(value).startswith("Unknown"):
                            op[field] = str(value)
                    else:
                        value = row.get(f"{field}_desc", row.get(field, 'N/A'))
                        op[field] = str(value) if value is not None else 'N/A'
            
            # Add IOCTL function if present and meaningful
            if 'smb2.ioctl.function' in frames.columns:
                ioctl_value = row.get('smb2.ioctl.function_desc', row.get('smb2.ioctl.function', ''))
                if ioctl_value and str(ioctl_value).strip() != "" and str(ioctl_value) != "N/A" and not str(ioctl_value).startswith("Unknown"):
                    op['smb2.ioctl.function'] = str(ioctl_value)
            
            operations.append(op)
        
        logger.info(f"Processed {len(operations)} operations in {time.time() - start_time:.2f}s")
        return operations
    
    def get_operations(self) -> List[Dict[str, Any]]:
        """Get current operations list."""
        return self.operations.copy()
    
    def get_session_frames(self) -> Optional[pd.DataFrame]:
        """Get current session frames."""
        return self.session_frames.copy() if self.session_frames is not None else None
    
    def clear_operations(self):
        """Clear current operations."""
        self.operations.clear()
        logger.debug("Cleared operations")
    
    def clear_session_frames(self):
        """Clear current session frames."""
        self.session_frames = None
        logger.debug("Cleared session frames")
    
    def get_execution_id(self) -> str:
        """Get unique execution ID."""
        return self.execution_id
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session.
        
        Returns:
            Dictionary with session summary information
        """
        if self.session_frames is None or self.session_frames.empty:
            return {
                "frame_count": 0,
                "session_id": None,
                "unique_commands": [],
                "unique_files": [],
                "time_range": None
            }
        
        try:
            # Get unique commands
            unique_commands = []
            if 'smb2.cmd' in self.session_frames.columns:
                cmd_values = self.session_frames['smb2.cmd'].dropna().unique()
                for cmd in cmd_values:
                    if isinstance(cmd, str) and cmd.isdigit():
                        cmd_int = int(cmd)
                        if cmd_int in SMB2_OP_NAME_DESC:
                            unique_commands.append(SMB2_OP_NAME_DESC[cmd_int][0])
            
            # Get unique files
            unique_files = []
            if 'smb2.filename' in self.session_frames.columns:
                unique_files = list(self.session_frames['smb2.filename'].dropna().unique())
                unique_files = [f for f in unique_files if f not in ['N/A', '']]
            
            # Get time range
            time_range = None
            if 'frame.time_epoch' in self.session_frames.columns:
                time_col = pd.to_numeric(self.session_frames['frame.time_epoch'], errors='coerce')
                time_range = {
                    "start": time_col.min(),
                    "end": time_col.max(),
                    "duration": time_col.max() - time_col.min()
                }
            
            # Get session ID
            session_id = None
            if 'smb2.sesid' in self.session_frames.columns:
                session_id = self.session_frames['smb2.sesid'].iloc[0] if len(self.session_frames) > 0 else None
            
            return {
                "frame_count": len(self.session_frames),
                "session_id": session_id,
                "unique_commands": unique_commands,
                "unique_files": unique_files[:10],  # Limit to first 10
                "time_range": time_range,
                "operations_count": len(self.operations)
            }
            
        except Exception as e:
            logger.error(f"Error generating session summary: {e}")
            return {
                "frame_count": len(self.session_frames) if self.session_frames is not None else 0,
                "session_id": None,
                "unique_commands": [],
                "unique_files": [],
                "time_range": None,
                "error": str(e)
            }


# Global session manager instance
_session_manager = None


def get_session_manager() -> SessionManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


# Convenience functions for backward compatibility
def load_capture() -> Optional[str]:
    """Load capture from configuration."""
    return get_session_manager().load_capture_path()


def get_output_dir(capture_path: str) -> Optional[str]:
    """Get output directory for capture."""
    return get_session_manager().get_output_directory(capture_path)


def list_session_files(output_dir: str) -> List[str]:
    """List session files in directory."""
    return get_session_manager().list_session_files(output_dir)


def load_and_summarize_session(capture_path: str, session_file: str) -> tuple:
    """Load and summarize a session."""
    return get_session_manager().load_and_summarize_session(capture_path, session_file)


def update_operations(capture_path: str, session_file: str, 
                     selected_file: Optional[str] = None, 
                     selected_fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Update operations for session."""
    return get_session_manager().update_operations(capture_path, session_file, selected_file, selected_fields)


def get_operations() -> List[Dict[str, Any]]:
    """Get current operations."""
    return get_session_manager().get_operations()


def get_session_frames() -> Optional[pd.DataFrame]:
    """Get current session frames."""
    return get_session_manager().get_session_frames() 