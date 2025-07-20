"""
Session Management Module.
Handles session loading, filtering, and operations management for SMB2 analysis.
Optimized for performance and memory efficiency.
"""

import os
import time
import uuid
import gc
from typing import List, Dict, Optional, Any
import pandas as pd
import pyarrow.parquet as pq
import numpy as np

from .config import get_config, get_logger, get_traces_folder
from .constants import (
    FIELD_MAPPINGS, shorten_path, normalize_path, get_tree_name_mapping,
    SMB2_OP_NAME_DESC
)
from .tshark_processor import create_session_directory

logger = get_logger()


class SessionManager:
    """Manages SMB2 sessions and operations with performance optimizations."""
    
    def __init__(self):
        self.operations = []
        self.session_frames = None
        self.execution_id = str(uuid.uuid4())
        self._tree_cache = {}  # Cache for tree mappings
        
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
        
        try:
            if not os.path.exists(output_dir):
                logger.warning(f"Output directory does not exist: {output_dir}")
                return []
            
            files = os.listdir(output_dir)
            session_files = [f for f in files if f.startswith('smb2_session_') and f.endswith('.parquet')]
            
            logger.info(f"Found {len(session_files)} session files")
            return sorted(session_files)
            
        except Exception as e:
            logger.error(f"Error listing session files: {e}")
            return []
    
    def load_session_by_file(self, session_file: str, output_dir: str) -> bool:
        """Load a session from a Parquet file with optimizations.
        
        Args:
            session_file: Name of the session file
            output_dir: Directory containing the session file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        logger.info(f"Loading session from file: {session_file}")
        
        try:
            session_path = os.path.join(output_dir, session_file)
            
            if not os.path.exists(session_path):
                logger.error(f"Session file not found: {session_path}")
                return False
            
            # Load with optimized settings
            table = pq.read_table(session_path)
            self.session_frames = table.to_pandas()
            
            # Optimize DataFrame dtypes for better performance
            self.session_frames = self._optimize_session_dtypes(self.session_frames)
            
            logger.info(f"Loaded session with {len(self.session_frames)} frames")
            logger.info(f"Session memory usage: {self.session_frames.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading session file {session_file}: {e}")
            return False
    
    def _optimize_session_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Optimize DataFrame data types for better performance.
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with optimized dtypes
        """
        logger.debug("Optimizing session DataFrame data types")
        
        initial_memory = df.memory_usage(deep=True).sum() / 1024**2
        
        # Optimize numeric columns
        numeric_cols = ['frame.number', 'tcp.stream']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce', downcast='integer')
        
        # Convert categorical columns for repeated values
        categorical_threshold = 0.5  # If less than 50% unique values
        for col in df.select_dtypes(include=['object']).columns:
            if col in df.columns and df[col].nunique() / len(df) < categorical_threshold:
                df[col] = df[col].astype('category')
        
        final_memory = df.memory_usage(deep=True).sum() / 1024**2
        memory_reduction = ((initial_memory - final_memory) / initial_memory) * 100
        
        logger.debug(f"Session memory optimization: {initial_memory:.2f}MB -> {final_memory:.2f}MB "
                    f"({memory_reduction:.1f}% reduction)")
        
        return df
    
    def get_operations_vectorized(self, selected_fields: Optional[List[str]] = None, 
                                 limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Extract operations from session frames using vectorized operations.
        
        Args:
            selected_fields: Optional list of additional fields to include
            limit: Optional limit on number of operations
            
        Returns:
            List of operation dictionaries
        """
        if self.session_frames is None or self.session_frames.empty:
            logger.warning("No session frames loaded")
            return []
        
        logger.info(f"Extracting operations from {len(self.session_frames)} frames using vectorized processing")
        
        start_time = time.time()
        frames = self.session_frames.copy()
        
        if limit:
            frames = frames.head(limit)
            logger.info(f"Limited processing to {limit} frames")
        
        # Get or generate tree mapping with caching
        tree_mapping = self._get_cached_tree_mapping(frames)
        
        # Vectorized field normalization
        frames_normalized = self._normalize_fields_vectorized(frames)
        
        # Extract operations using vectorized operations
        operations = self._extract_operations_vectorized(frames_normalized, tree_mapping, selected_fields)
        
        elapsed_time = time.time() - start_time
        logger.info(f"Extracted {len(operations)} operations in {elapsed_time:.2f}s using vectorized processing")
        
        return operations
    
    def _get_cached_tree_mapping(self, frames: pd.DataFrame) -> Dict[str, str]:
        """Get tree mapping with caching for better performance.
        
        Args:
            frames: DataFrame with session frames
            
        Returns:
            Dictionary mapping tree IDs to names
        """
        cache_key = f"tree_mapping_{len(frames)}"
        
        if cache_key in self._tree_cache:
            logger.debug("Using cached tree mapping")
            return self._tree_cache[cache_key]
        
        logger.debug("Generating new tree mapping")
        tree_mapping = get_tree_name_mapping(frames)
        
        # Cache the mapping
        self._tree_cache[cache_key] = tree_mapping
        
        return tree_mapping
    
    def _normalize_fields_vectorized(self, frames: pd.DataFrame) -> pd.DataFrame:
        """Normalize fields using vectorized operations.
        
        Args:
            frames: Input DataFrame
            
        Returns:
            DataFrame with normalized fields
        """
        logger.debug("Normalizing fields using vectorized operations")
        
        # Vectorized field normalization
        normalized_frames = frames.copy()
        
        # Normalize filename field
        if 'smb2.filename' in normalized_frames.columns:
            normalized_frames['smb2.filename_normalized'] = normalized_frames['smb2.filename'].fillna('N/A').apply(
                lambda x: x.split(',')[0].strip() if isinstance(x, str) and x.strip() else "N/A"
            )
        else:
            normalized_frames['smb2.filename_normalized'] = "N/A"
        
        # Normalize tid field
        if 'smb2.tid' in normalized_frames.columns:
            normalized_frames['smb2.tid_normalized'] = normalized_frames['smb2.tid'].fillna('N/A').apply(
                lambda x: x.split(',')[0].strip() if isinstance(x, str) and x.strip() else "N/A"
            )
        else:
            normalized_frames['smb2.tid_normalized'] = "N/A"
        
        # Normalize status description
        if 'smb2.nt_status_desc' in normalized_frames.columns:
            normalized_frames['status_display'] = normalized_frames['smb2.nt_status_desc'].fillna('N/A')
            normalized_frames['status_desc'] = normalized_frames['status_display'].apply(
                lambda x: x.split('(')[0].strip() if isinstance(x, str) and x != 'N/A' else 'Not applicable'
            )
        else:
            normalized_frames['status_display'] = 'N/A'
            normalized_frames['status_desc'] = 'Not applicable'
        
        # Create path from filename
        normalized_frames['path'] = normalized_frames['smb2.filename_normalized'].apply(
            lambda x: shorten_path(x) if x != "N/A" else "N/A"
        )
        
        return normalized_frames
    
    def _extract_operations_vectorized(self, frames: pd.DataFrame, tree_mapping: Dict[str, str], 
                                     selected_fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extract operations using vectorized operations.
        
        Args:
            frames: Normalized DataFrame
            tree_mapping: Tree ID to name mapping
            selected_fields: Optional additional fields
            
        Returns:
            List of operation dictionaries
        """
        operations = []
        
        # Define mandatory fields for operations
        mandatory_fields = [
            'frame.number', 'smb2.cmd', 'smb2.filename', 'smb2.tid', 
            'smb2.nt_status', 'smb2.flags.response', 'smb2.fid'
        ]
        
        # Get tree names vectorized
        frames['tree_name'] = frames['smb2.tid_normalized'].map(tree_mapping).fillna(frames['smb2.tid_normalized'])
        
        # Vectorized operation name mapping
        frames['op_name'] = frames.get('smb2.cmd_desc', 'Unknown').fillna('Unknown')
        
        # Create base operations structure efficiently
        for idx in frames.index:
            row = frames.loc[idx]
            
            # Create operation dictionary efficiently
            op = {
                'Frame': row.get('frame.number', 'N/A'),
                'Command': row['op_name'],
                'Path': row['path'],
                'Status': row['status_display'],
                'StatusDesc': row['status_desc'],
                'Tree': row['tree_name'],
                'orig_idx': idx,
                # Add required fields for replay validation
                'smb2.cmd': row.get('smb2.cmd', '-1'),
                'smb2.filename': row['smb2.filename_normalized'],
                'smb2.tid': row['smb2.tid_normalized'],
                'smb2.nt_status': row.get('smb2.nt_status', 'N/A'),
                'smb2.flags.response': row.get('smb2.flags.response', 'False'),
                'smb2.fid': row.get('smb2.fid', 'N/A')
            }
            
            # Add selected fields efficiently
            if selected_fields:
                for field in selected_fields:
                    if field not in mandatory_fields:
                        if field in ["smb2.create.action", "smb2.ioctl.function"]:
                            value = row.get(f"{field}_desc", row.get(field, ""))
                        else:
                            value = row.get(field, "")
                        
                        if value and str(value).strip() and str(value) != 'N/A':
                            if isinstance(value, list):
                                value = ', '.join(str(v) for v in value if v)
                            op[field] = str(value).strip()
            
            operations.append(op)
        
        return operations
    
    # Maintain backward compatibility
    def get_operations(self, selected_fields: Optional[List[str]] = None, 
                      limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get operations using optimized vectorized processing."""
        return self.get_operations_vectorized(selected_fields, limit)
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get session summary with performance metrics.
        
        Returns:
            Dictionary with session summary information
        """
        if self.session_frames is None or self.session_frames.empty:
            return {
                "total_frames": 0,
                "unique_commands": [],
                "session_id": None,
                "memory_usage_mb": 0,
                "optimization_applied": True
            }
        
        logger.debug("Generating session summary with performance metrics")
        
        # Get unique commands efficiently
        unique_commands = []
        if 'smb2.cmd' in self.session_frames.columns:
            cmd_values = self.session_frames['smb2.cmd'].dropna().unique()
            for cmd_str in cmd_values:
                try:
                    if isinstance(cmd_str, list):
                        cmd_ints = [int(c) for c in cmd_str if str(c).isdigit()]
                    else:
                        cmd_ints = [int(cmd_str)] if str(cmd_str).isdigit() else []
                    
                    for cmd_int in cmd_ints:
                        if cmd_int in SMB2_OP_NAME_DESC:
                            unique_commands.append(SMB2_OP_NAME_DESC[cmd_int][0])
                except (ValueError, TypeError):
                    continue
        
        # Remove duplicates while preserving order
        unique_commands = list(dict.fromkeys(unique_commands))
        
        # Get session ID efficiently
        session_id = None
        if 'smb2.sesid' in self.session_frames.columns and len(self.session_frames) > 0:
            first_sesid = self.session_frames['smb2.sesid'].iloc[0]
            if first_sesid and not pd.isna(first_sesid):
                session_id = first_sesid
        
        # Calculate memory usage
        memory_mb = self.session_frames.memory_usage(deep=True).sum() / 1024**2
        
        summary = {
            "total_frames": len(self.session_frames),
            "unique_commands": unique_commands,
            "session_id": session_id,
            "memory_usage_mb": round(memory_mb, 2),
            "optimization_applied": True,
            "columns": len(self.session_frames.columns)
        }
        
        logger.info(f"Session summary: {summary['total_frames']} frames, "
                   f"{len(summary['unique_commands'])} unique commands, "
                   f"{summary['memory_usage_mb']} MB")
        
        return summary

    def clear_cache(self):
        """Clear internal caches to free memory."""
        self._tree_cache.clear()
        if hasattr(self, 'session_frames') and self.session_frames is not None:
            del self.session_frames
            self.session_frames = None
        gc.collect()
        logger.debug("Cleared session manager caches")


def get_session_manager() -> SessionManager:
    """Get a new session manager instance."""
    return SessionManager() 