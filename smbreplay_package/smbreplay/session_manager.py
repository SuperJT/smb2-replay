"""
Session Management Module.
Handles session loading, filtering, and operations management for SMB2 analysis.
Optimized for performance and memory efficiency.
"""

import gc

import os
import pandas as pd
import pyarrow.parquet as pq
import time
import uuid
from typing import Any, Dict, List, Optional

from .config import get_config, get_logger
from .constants import (
    FIELD_MAPPINGS,
    SMB2_OP_NAME_DESC,
    get_tree_name_mapping,
    normalize_path,
    shorten_path,
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
            if "cases" in parts:
                cases_index = parts.index("cases")
                if cases_index + 1 < len(parts):
                    case_number = parts[cases_index + 1]

            trace_name = os.path.basename(capture_path).split(".")[0]

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
            session_files = [
                f
                for f in files
                if f.startswith("smb2_session_") and f.endswith(".parquet")
            ]

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
            logger.info(
                f"Session memory usage: {self.session_frames.memory_usage(deep=True).sum() / 1024**2:.2f} MB"
            )

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
        numeric_cols = ["frame.number", "tcp.stream"]
        for col in numeric_cols:
            if col in df.columns:
                try:
                    df[col] = pd.to_numeric(
                        df[col], errors="coerce", downcast="integer"
                    )
                except Exception as e:
                    logger.debug(f"Could not optimize numeric column {col}: {e}")

        # Convert categorical columns for repeated values with safe handling
        categorical_threshold = 0.5  # If less than 50% unique values
        for col in df.select_dtypes(include=["object"]).columns:
            if col in df.columns:
                try:
                    # Check if column is suitable for categorical conversion
                    if df[col].nunique() / len(df) < categorical_threshold:
                        # Handle existing categorical columns safely
                        if df[col].dtype.name == "category":
                            # Already categorical, skip
                            continue
                        else:
                            # Convert to categorical with error handling
                            df[col] = df[col].astype("category")
                except Exception as e:
                    logger.debug(f"Could not convert column {col} to categorical: {e}")
                    # Continue with other columns

        final_memory = df.memory_usage(deep=True).sum() / 1024**2
        memory_reduction = ((initial_memory - final_memory) / initial_memory) * 100

        logger.debug(
            f"Session memory optimization: {initial_memory:.2f}MB -> {final_memory:.2f}MB "
            f"({memory_reduction:.1f}% reduction)"
        )

        return df

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
            # Load with optimized settings
            table = pq.read_table(session_path)
            self.session_frames = table.to_pandas()

            # Optimize DataFrame dtypes for better performance
            self.session_frames = self._optimize_session_dtypes(self.session_frames)

            logger.info(
                f"Loaded session {session_file} with {len(self.session_frames)} frames"
            )
            logger.info(
                f"Session memory usage: {self.session_frames.memory_usage(deep=True).sum() / 1024**2:.2f} MB"
            )

        except Exception as e:
            logger.error(f"Error loading session file: {e}")
            return None, [], [], []

        if self.session_frames.empty:
            logger.warning(f"No frames found in session {session_file}")
            return None, [], [], []

        # Get field options
        all_fields = sorted(
            [col for col in self.session_frames.columns if col.startswith("smb2.")]
        )
        volatile_fields = ["smb2.time", "smb2.frame.time"]
        field_options = [f for f in all_fields if f not in volatile_fields]

        # Default selected fields
        default_fields = ["smb2.nt_status", "smb2.create.action"]
        selected_fields = [f for f in default_fields if f in field_options]

        # Get file options
        unique_files = sorted(
            set(self.session_frames.get("smb2.filename", pd.Series([])).dropna())
            - {"N/A", ""}
        )
        file_options = unique_files

        logger.debug(f"Field options: {len(field_options)} fields available")
        logger.debug(f"File options: {len(file_options)} files available")

        return self.session_frames, field_options, file_options, selected_fields

    def get_operations_vectorized(
        self, selected_fields: Optional[List[str]] = None, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
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

        logger.info(
            f"Extracting operations from {len(self.session_frames)} frames using vectorized processing"
        )

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
        operations = self._extract_operations_vectorized(
            frames_normalized, tree_mapping, selected_fields
        )

        elapsed_time = time.time() - start_time
        logger.info(
            f"Extracted {len(operations)} operations in {elapsed_time:.2f}s using vectorized processing"
        )

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
        if "smb2.filename" in normalized_frames.columns:
            normalized_frames["smb2.filename_normalized"] = (
                normalized_frames["smb2.filename"]
                .fillna("N/A")
                .apply(
                    lambda x: (
                        x.split(",")[0].strip()
                        if isinstance(x, str) and x.strip()
                        else "N/A"
                    )
                )
            )
        else:
            normalized_frames["smb2.filename_normalized"] = "N/A"

        # Normalize tid field
        if "smb2.tid" in normalized_frames.columns:
            normalized_frames["smb2.tid_normalized"] = (
                normalized_frames["smb2.tid"]
                .fillna("N/A")
                .apply(
                    lambda x: (
                        x.split(",")[0].strip()
                        if isinstance(x, str) and x.strip()
                        else "N/A"
                    )
                )
            )
        else:
            normalized_frames["smb2.tid_normalized"] = "N/A"

        # Normalize status description
        if "smb2.nt_status_desc" in normalized_frames.columns:
            normalized_frames["status_display"] = normalized_frames[
                "smb2.nt_status_desc"
            ].fillna("N/A")
            normalized_frames["status_desc"] = normalized_frames[
                "status_display"
            ].apply(
                lambda x: (
                    x.split("(")[0].strip()
                    if isinstance(x, str) and x != "N/A"
                    else "Not applicable"
                )
            )
        else:
            normalized_frames["status_display"] = "N/A"
            normalized_frames["status_desc"] = "Not applicable"

        # Create path from filename
        normalized_frames["path"] = normalized_frames["smb2.filename_normalized"].apply(
            lambda x: shorten_path(x) if x != "N/A" else "N/A"
        )

        return normalized_frames

    def _extract_operations_vectorized(
        self,
        frames: pd.DataFrame,
        tree_mapping: Dict[str, str],
        selected_fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
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
            "frame.number",
            "smb2.cmd",
            "smb2.filename",
            "smb2.tid",
            "smb2.nt_status",
            "smb2.flags.response",
            "smb2.fid",
        ]

        # Get tree names vectorized
        frames["tree_name"] = (
            frames["smb2.tid_normalized"]
            .map(tree_mapping)
            .fillna(frames["smb2.tid_normalized"])
        )

        # Vectorized operation name mapping
        normalize_cmd = FIELD_MAPPINGS["smb2.cmd"]["normalize"]
        cmd_mapping = FIELD_MAPPINGS["smb2.cmd"]["mapping"]

        def get_op_name(x):
            if x and pd.notna(x):
                try:
                    normalized = normalize_cmd(x)
                    result = cmd_mapping.get(normalized, f"UNKNOWN({x})")
                    logger.debug(
                        f"Command translation: {x} -> {normalized} -> {result}"
                    )
                    return result
                except Exception as e:
                    logger.debug(f"Error translating command {x}: {e}")
                    return f"UNKNOWN({x})"
            return "UNKNOWN"

        frames["op_name"] = frames["smb2.cmd"].apply(get_op_name)

        # Create base operations structure efficiently
        for idx in frames.index:
            row = frames.loc[idx]

            # Create operation dictionary efficiently
            op = {
                "Frame": row.get("frame.number", "N/A"),
                "Command": row["op_name"],
                "Path": row["path"],
                "Status": row["status_display"],
                "StatusDesc": row["status_desc"],
                "Tree": row["tree_name"],
                "orig_idx": idx,
                # Add required fields for replay validation
                "smb2.cmd": row.get("smb2.cmd", "-1"),
                "smb2.filename": row["smb2.filename_normalized"],
                "smb2.tid": row["smb2.tid_normalized"],
                "smb2.nt_status": row.get("smb2.nt_status", "N/A"),
                "smb2.flags.response": row.get("smb2.flags.response", "False"),
                "smb2.fid": row.get("smb2.fid", "N/A"),
            }

            # Add selected fields efficiently
            if selected_fields:
                for field in selected_fields:
                    if field not in mandatory_fields:
                        if field in ["smb2.create.action", "smb2.ioctl.function"]:
                            value = row.get(f"{field}_desc", row.get(field, ""))
                        else:
                            value = row.get(field, "")

                        if value and str(value).strip() and str(value) != "N/A":
                            if isinstance(value, list):
                                value = ", ".join(str(v) for v in value if v)
                            op[field] = str(value).strip()

            operations.append(op)

        return operations

    def update_operations(
        self,
        capture_path: str,
        session_file: str,
        selected_file: Optional[str] = None,
        selected_fields: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
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
        logger.info(
            f"Preparing operations for session: {session_file}, file: {selected_file}"
        )

        # Load session if not already loaded
        if self.session_frames is None or self.session_frames.empty:
            self.session_frames, _, _, _ = self.load_and_summarize_session(
                capture_path, session_file
            )
            if self.session_frames is None or self.session_frames.empty:
                logger.warning(f"Failed to load session data for {session_file}")
                return []

        # Default selected fields
        if selected_fields is None:
            selected_fields = ["smb2.nt_status", "smb2.create.action"]

        # Filter invalid fields
        selected_fields = [
            f for f in selected_fields if f in self.session_frames.columns
        ]

        # Apply field mappings for normalization
        filtered_frames = self.session_frames.copy()

        # Apply field mappings with safe categorical handling
        for field in FIELD_MAPPINGS:
            if field in filtered_frames.columns:
                mapping = FIELD_MAPPINGS[field]["mapping"]
                normalize = FIELD_MAPPINGS[field]["normalize"]

                logger.debug(f"Normalizing field: {field}")

                # Handle categorical columns safely
                try:
                    if filtered_frames[field].dtype.name == "category":
                        # Convert categorical to object, apply function, then back to categorical if needed
                        temp_series = (
                            filtered_frames[field].astype("object").apply(normalize)
                        )
                        # Only convert back to categorical if it makes sense (few unique values)
                        if temp_series.nunique() / len(temp_series) < 0.5:
                            filtered_frames[field] = temp_series.astype("category")
                        else:
                            filtered_frames[field] = temp_series
                    else:
                        filtered_frames[field] = filtered_frames[field].apply(normalize)
                except Exception as e:
                    logger.debug(f"Error normalizing field {field}: {e}")
                    # Continue with other fields
                    continue

                # Handle special fields
                if field in ["smb2.create.action", "smb2.ioctl.function"]:
                    if not isinstance(mapping, dict):
                        logger.error(
                            f"FIELD_MAPPINGS['{field}']['mapping'] must be a dict, got {type(mapping)}"
                        )
                        continue
                    try:
                        filtered_frames[f"{field}_desc"] = filtered_frames[field].apply(
                            lambda x: (
                                mapping.get(str(x), "")
                                if pd.notna(x)
                                and str(x).strip() != ""
                                and str(x) != "None"
                                else ""
                            )
                        )
                    except Exception as e:
                        logger.debug(f"Error creating description for {field}: {e}")
                        filtered_frames[f"{field}_desc"] = ""
                else:
                    try:
                        filtered_frames[f"{field}_desc"] = (
                            filtered_frames[field]
                            .map(mapping)
                            .fillna(
                                filtered_frames[field].apply(
                                    lambda x: f"Unknown ({x})" if pd.notna(x) else ""
                                )
                            )
                        )
                    except Exception as e:
                        logger.debug(f"Error mapping field {field}: {e}")
                        filtered_frames[f"{field}_desc"] = filtered_frames[
                            field
                        ].astype(str)

        # Filter frames based on selected file
        if selected_file and selected_file.strip():
            filtered_frames = filtered_frames[
                filtered_frames["smb2.filename"].apply(normalize_path)
                == normalize_path(selected_file)
            ]
            logger.debug(
                f"Filtered to {len(filtered_frames)} frames for file: {selected_file}"
            )
        else:
            logger.info("No file filter applied, processing all frames")

        if filtered_frames.empty and selected_file:
            logger.warning(f"No operations found for file: {selected_file}")
            return []

        # Process frames into operations using optimized method
        self.operations = self._process_frames_to_operations(
            filtered_frames, selected_fields
        )

        logger.info(f"Processed {len(self.operations)} operations")
        return self.operations

    def _process_frames_to_operations(
        self, frames: pd.DataFrame, selected_fields: List[str]
    ) -> List[Dict[str, Any]]:
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

        # Get tree name mapping with caching
        tree_mapping = self._get_cached_tree_mapping(frames)
        logger.debug(f"Tree mapping: {tree_mapping}")

        mandatory_fields = [
            "frame.number",
            "smb2.cmd",
            "smb2.filename",
            "smb2.nt_status",
            "smb2.flags.response",
        ]

        def normalize_field(field_str):
            """Normalize field values."""
            if pd.isna(field_str) or not field_str or field_str.strip() == "":
                return "N/A"
            return field_str.split(",")[0].strip()

        for idx, row in frames.iterrows():
            if idx % 10000 == 0 and idx > 0:
                logger.debug(f"Processing frame {idx}/{total_frames}")

            # Normalize basic fields
            filename = normalize_field(row.get("smb2.filename", "N/A"))
            tid = normalize_field(row.get("smb2.tid", "N/A"))
            path = shorten_path(filename) if filename != "N/A" else "N/A"

            # Get tree name from mapping - normalize tid for consistent lookup
            tree_name = tree_mapping.get(str(tid), tid) if tid != "N/A" else "N/A"

            # Use mapped and normalized fields
            status_display = row.get("smb2.nt_status_desc", "N/A")
            cmd = row.get("smb2.cmd", "-1")
            is_response = row.get("smb2.flags.response", "False") == "True"

            # Get command name using the same logic as vectorized method
            try:
                if cmd and pd.notna(cmd):
                    # Use SMB2_OP_NAME_DESC directly for simplicity
                    cmd_int = int(
                        float(
                            str(cmd)
                            .split(",")[0]
                            .strip()
                            .replace("{", "")
                            .replace("}", "")
                            .replace("'", "")
                        )
                    )
                    op_name = SMB2_OP_NAME_DESC.get(cmd_int, (f"UNKNOWN({cmd})", ""))[0]
                else:
                    op_name = "UNKNOWN"
            except Exception as e:
                logger.debug(f"Error translating command {cmd}: {e}")
                op_name = f"UNKNOWN({cmd})" if cmd else "UNKNOWN"

            # Handle status description
            status_desc = (
                status_display.split("(")[0].strip()
                if status_display != "N/A"
                else "Not applicable"
            )

            # Create operation dictionary
            op = {
                "Frame": row.get("frame.number", "N/A"),
                "Command": op_name,
                "Path": path,
                "Status": status_display,
                "StatusDesc": status_desc,
                "Tree": tree_name,
                "orig_idx": idx,
                # Add fields required for replay validation
                "smb2.cmd": cmd,
                "smb2.filename": filename,
                "smb2.tid": tid,
                "smb2.nt_status": row.get("smb2.nt_status", "N/A"),
                "smb2.flags.response": row.get("smb2.flags.response", "False"),
                "smb2.fid": row.get("smb2.fid", "N/A"),
                "smb2.msg_id": row.get("smb2.msg_id", "N/A"),
                "is_response": is_response,
            }

            # Add selected fields
            for field in selected_fields:
                if field not in mandatory_fields:
                    # Special handling for meaningful fields only
                    if field in ["smb2.create.action", "smb2.ioctl.function"]:
                        value = row.get(f"{field}_desc", row.get(field, ""))
                        if (
                            value
                            and str(value).strip() != ""
                            and str(value) != "N/A"
                            and not str(value).startswith("Unknown")
                        ):
                            op[field] = str(value)
                    else:
                        value = row.get(f"{field}_desc", row.get(field, "N/A"))
                        op[field] = str(value) if value is not None else "N/A"

            # Add IOCTL function if present and meaningful
            if "smb2.ioctl.function" in frames.columns:
                ioctl_value = row.get(
                    "smb2.ioctl.function_desc", row.get("smb2.ioctl.function", "")
                )
                if (
                    ioctl_value
                    and str(ioctl_value).strip() != ""
                    and str(ioctl_value) != "N/A"
                    and not str(ioctl_value).startswith("Unknown")
                ):
                    op["smb2.ioctl.function"] = str(ioctl_value)

            operations.append(op)

        logger.info(
            f"Processed {len(operations)} operations in {time.time() - start_time:.2f}s"
        )
        return operations

    # Maintain backward compatibility while using optimized functions
    def get_operations(
        self, selected_fields: Optional[List[str]] = None, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get operations using optimized vectorized processing."""
        return self.get_operations_vectorized(selected_fields, limit)

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
                "optimization_applied": True,
            }

        logger.debug("Generating session summary with performance metrics")

        # Get unique commands efficiently
        unique_commands = []
        if "smb2.cmd" in self.session_frames.columns:
            cmd_values = self.session_frames["smb2.cmd"].dropna().unique()
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
        if "smb2.sesid" in self.session_frames.columns and len(self.session_frames) > 0:
            first_sesid = self.session_frames["smb2.sesid"].iloc[0]
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
            "columns": len(self.session_frames.columns),
        }

        logger.info(
            f"Session summary: {summary['total_frames']} frames, "
            f"{len(summary['unique_commands'])} unique commands, "
            f"{summary['memory_usage_mb']} MB"
        )

        return summary

    def clear_cache(self):
        """Clear internal caches to free memory."""
        self._tree_cache.clear()
        if hasattr(self, "session_frames") and self.session_frames is not None:
            del self.session_frames
            self.session_frames = None
        gc.collect()
        logger.debug("Cleared session manager caches")


# Global session manager instance
_session_manager: Optional[SessionManager] = None


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


def update_operations(
    capture_path: str,
    session_file: str,
    selected_file: Optional[str] = None,
    selected_fields: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Update operations for session."""
    return get_session_manager().update_operations(
        capture_path, session_file, selected_file, selected_fields
    )


def get_operations() -> List[Dict[str, Any]]:
    """Get current operations."""
    return get_session_manager().get_operations()


def get_session_frames() -> Optional[pd.DataFrame]:
    """Get current session frames."""
    return get_session_manager().get_session_frames()
