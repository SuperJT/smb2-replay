"""
Session Management Module.
Handles session loading, filtering, and operations management for SMB2 analysis.
Optimized for performance and memory efficiency.
"""

import asyncio
import contextlib
import gc
import os
import time
import uuid
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow.parquet as pq

from .config import get_config, get_logger
from .constants import (
    FIELD_MAPPINGS,
    SMB2_OP_NAME_DESC,
    get_tree_name_mapping,
    normalize_path,
    shorten_path,
)
from .database import get_database_client
from .tshark_processor import create_session_directory

logger = get_logger()


class SessionManager:
    """Manages SMB2 sessions and operations with performance optimizations."""

    def __init__(self):
        self.operations = []
        self.session_frames = None
        self.execution_id = str(uuid.uuid4())
        self._tree_cache = {}  # Cache for tree mappings

    def load_capture_path(self) -> str | None:
        """Load capture path from config or environment."""
        logger.info("Loading capture path from configuration")

        config = get_config()
        capture = config.get_capture_path()

        if capture and Path(capture).exists():
            logger.info(f"Loaded capture path: {capture}")
            return capture

        logger.warning("No valid capture path found in configuration")
        return None

    def get_output_directory(self, capture_path: str) -> str | None:
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
            capture_path_obj = Path(capture_path).resolve()

            # Extract case number from capture path
            case_number = "local_case"  # Default for local development
            parts = capture_path_obj.parts
            # Check for both "cases" (local) and "stingray" (Docker) folders
            for folder_name in ["cases", "stingray"]:
                if folder_name in parts:
                    folder_index = parts.index(folder_name)
                    if folder_index + 1 < len(parts):
                        case_number = parts[folder_index + 1]
                        break

            trace_name = capture_path_obj.stem

            # Use create_session_directory from tshark_processor
            output_dir = create_session_directory(case_number, trace_name)

            # Verify directory exists and is writable
            if not Path(output_dir).exists():
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

    async def _list_sessions_from_database(
        self, case_number: str, trace_name: str
    ) -> list[str]:
        """List sessions from PostgreSQL database.

        Args:
            case_number: Case number
            trace_name: Trace name

        Returns:
            List of session IDs (formatted as smb2_session_<sesid>.parquet for compatibility)
        """
        try:
            db = get_database_client()

            # Get trace record
            trace = await db.get_trace_by_path(case_number, trace_name)
            if not trace:
                logger.warning(
                    f"No trace found in database for {case_number}/{trace_name}"
                )
                return []

            # Get all sessions for this trace
            sessions = await db.list_sessions_for_trace(trace["id"])

            # Format session IDs to match Parquet file naming
            session_files = [
                f"smb2_session_{session['sessionId']}.parquet" for session in sessions
            ]

            logger.info(
                f"Found {len(session_files)} sessions in database for {case_number}/{trace_name}"
            )
            return sorted(session_files)

        except Exception as e:
            logger.debug(f"Error listing sessions from database: {e}")
            return []

    def list_session_files(self, output_dir: str) -> list[str]:
        """List session files from database or Parquet files.

        In database mode (USE_DATABASE=true): Queries PostgreSQL only
        In Parquet mode (USE_DATABASE=false): Reads Parquet files only

        Args:
            output_dir: Directory containing session files

        Returns:
            List of session file names
        """
        logger.info(f"Listing session files for {output_dir}")

        use_database = os.getenv("USE_DATABASE", "true").lower() == "true"

        if use_database:
            # Database-only mode
            try:
                # Extract case number and trace name from output_dir path
                # Expected format: /.../case_number/.tracer/trace_name/sessions
                parts = Path(output_dir).parts
                if ".tracer" in parts:
                    tracer_index = parts.index(".tracer")
                    if tracer_index > 0 and tracer_index + 1 < len(parts):
                        case_number = parts[tracer_index - 1]
                        trace_name = parts[tracer_index + 1]

                        logger.debug(
                            f"Querying database for sessions: {case_number}/{trace_name}"
                        )
                        session_files = asyncio.run(
                            self._list_sessions_from_database(case_number, trace_name)
                        )

                        if session_files:
                            logger.info(
                                f"Found {len(session_files)} sessions in database"
                            )
                            return session_files
                        else:
                            logger.warning(
                                f"No sessions found in database for {case_number}/{trace_name}"
                            )
                            return []
            except Exception as e:
                logger.error(f"Error querying database: {e}")
                return []
        else:
            # Parquet-only mode (legacy)
            try:
                output_dir_path = Path(output_dir)
                if not output_dir_path.exists():
                    logger.warning(f"Output directory does not exist: {output_dir}")
                    return []

                session_files = [
                    f.name
                    for f in output_dir_path.iterdir()
                    if f.name.startswith("smb2_session_") and f.name.endswith(".parquet")
                ]

                logger.info(f"Found {len(session_files)} session files in {output_dir}")
                return sorted(session_files)

            except Exception as e:
                logger.error(f"Error listing session files: {e}")
                return []

    async def _load_session_from_database(
        self, case_number: str, trace_name: str, session_id: str
    ) -> pd.DataFrame | None:
        """Load session frames from PostgreSQL database.

        Args:
            case_number: Case number
            trace_name: Trace name
            session_id: Session ID

        Returns:
            DataFrame with session frames or None if not found
        """
        try:
            db = get_database_client()

            # Get trace record
            trace = await db.get_trace_by_path(case_number, trace_name)
            if not trace:
                logger.warning(
                    f"No trace found in database for {case_number}/{trace_name}"
                )
                return None

            # Get session frames
            df = await db.get_session_frames(trace["id"], session_id)
            return df

        except Exception as e:
            logger.debug(f"Error loading session from database: {e}")
            return None

    def load_session_by_file(self, session_file: str, output_dir: str) -> bool:
        """Load a session from database or Parquet file.

        Tries database first, falls back to Parquet files if database unavailable.

        Args:
            session_file: Name of the session file (e.g., smb2_session_0x1234567890abcdef.parquet)
            output_dir: Directory containing the session file

        Returns:
            True if loaded successfully, False otherwise
        """
        logger.info(f"Loading session from file: {session_file}")

        # Extract session ID from filename
        # Format: smb2_session_<sesid>.parquet
        try:
            if session_file.startswith("smb2_session_") and session_file.endswith(
                ".parquet"
            ):
                session_id = session_file[len("smb2_session_") : -len(".parquet")]

                # Try database first if enabled
                if os.getenv("USE_DATABASE", "true").lower() == "true":
                    parts = Path(output_dir).parts
                    if ".tracer" in parts:
                        tracer_index = parts.index(".tracer")
                        if tracer_index > 0 and tracer_index + 1 < len(parts):
                            case_number = parts[tracer_index - 1]
                            trace_name = parts[tracer_index + 1]

                            logger.debug(
                                f"Attempting to load session {session_id} from database"
                            )
                            df = asyncio.run(
                                self._load_session_from_database(
                                    case_number, trace_name, session_id
                                )
                            )

                            if df is not None:
                                self.session_frames = self._optimize_session_dtypes(df)
                                logger.info(
                                    f"Loaded session with {len(self.session_frames)} frames from database"
                                )
                                logger.info(
                                    f"Session memory usage: {self.session_frames.memory_usage(deep=True).sum() / 1024**2:.2f} MB"
                                )
                                return True
                            logger.debug("Session not in database, trying Parquet file")
        except Exception as e:
            logger.debug(f"Could not query database, falling back to Parquet file: {e}")

        # Fallback to Parquet file
        try:
            session_path = Path(output_dir) / session_file

            if not session_path.exists():
                logger.error(f"Session file not found: {session_path}")
                return False

            # Load with optimized settings
            table = pq.read_table(str(session_path))
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

        Uses database-aware load_session_by_file which tries PostgreSQL first,
        then falls back to Parquet files.

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

        # Use database-aware loading (tries DB first, falls back to Parquet)
        if not self.load_session_by_file(session_file, output_dir):
            logger.warning(f"Failed to load session: {session_file}")
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
        self, selected_fields: list[str] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
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

    def _get_cached_tree_mapping(self, frames: pd.DataFrame) -> dict[str, str]:
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
        tree_mapping: dict[str, str],
        selected_fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
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
            try:
                # Handle None/NaN early - use try/except for numpy array edge cases
                if x is None:
                    return "UNKNOWN"
                try:
                    if pd.isna(x):
                        return "UNKNOWN"
                except (ValueError, TypeError):
                    pass  # numpy arrays raise ValueError, continue processing

                # Handle collection types: list, set, tuple, or numpy array
                # Note: Parquet returns numpy arrays, not Python lists
                # Use pd.api.types.is_list_like which handles all array-like types
                if pd.api.types.is_list_like(x) and not isinstance(x, str):
                    if len(x) > 0:
                        # Translate ALL commands and join with comma
                        names = []
                        for cmd in list(x):
                            try:
                                normalized = str(int(str(cmd).strip()))
                                name = cmd_mapping.get(normalized, f"UNKNOWN({cmd})")
                                names.append(name)
                            except (ValueError, TypeError):
                                names.append(f"UNKNOWN({cmd})")
                        result = ", ".join(names)
                        logger.debug(
                            f"Command translation (collection): {x} -> {result}"
                        )
                        return result
                    return "UNKNOWN"

                # Handle string representations of lists/sets: "['5', '15']" or "['5' '15']"
                x_str = str(x).strip()
                if x_str.startswith(("[", "{")):
                    # Parse string-encoded collection: extract all numbers
                    # Clean brackets and quotes, split by comma or space (numpy uses spaces)
                    cleaned = (
                        x_str.replace("[", "")
                        .replace("]", "")
                        .replace("{", "")
                        .replace("}", "")
                        .replace("'", "")
                        .replace('"', "")
                    )
                    # Split by comma first, then by space (numpy arrays use spaces)
                    parts = cleaned.split(",") if "," in cleaned else cleaned.split()
                    if parts:
                        # Translate ALL commands and join with comma
                        names = []
                        for part in parts:
                            cmd = part.strip()
                            if cmd:
                                try:
                                    normalized = str(int(cmd))
                                    name = cmd_mapping.get(
                                        normalized, f"UNKNOWN({cmd})"
                                    )
                                    names.append(name)
                                except (ValueError, TypeError):
                                    names.append(f"UNKNOWN({cmd})")
                        if names:
                            result = ", ".join(names)
                            logger.debug(
                                f"Command translation (string-list): {x} -> {result}"
                            )
                            return result
                    return "UNKNOWN"

                # Original string handling via normalize lambda
                normalized = normalize_cmd(x)
                result = cmd_mapping.get(normalized, f"UNKNOWN({x})")
                logger.debug(f"Command translation: {x} -> {normalized} -> {result}")
                return result
            except Exception as e:
                logger.debug(f"Error translating command {x}: {e}")
                return f"UNKNOWN({x})"

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
        selected_file: str | None = None,
        selected_fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
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
                        # Guard against division by zero when series is empty
                        series_len = len(temp_series)
                        if series_len > 0 and temp_series.nunique() / series_len < 0.5:
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
                        # Use default argument m=mapping to capture loop variable by value
                        filtered_frames[f"{field}_desc"] = filtered_frames[field].apply(
                            lambda x, m=mapping: (
                                m.get(str(x), "")
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
        self, frames: pd.DataFrame, selected_fields: list[str]
    ) -> list[dict[str, Any]]:
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
            op_name = "UNKNOWN"
            try:
                # Handle None early
                if cmd is None or (not pd.api.types.is_list_like(cmd) and pd.isna(cmd)):
                    pass  # op_name already set to UNKNOWN
                # Handle collection types: list, set, tuple, or numpy array
                elif pd.api.types.is_list_like(cmd) and not isinstance(cmd, str):
                    if len(cmd) > 0:
                        # Translate ALL commands and join with comma
                        names = []
                        for c in list(cmd):
                            try:
                                cmd_int = int(str(c).strip())
                                name = SMB2_OP_NAME_DESC.get(
                                    cmd_int, (f"UNKNOWN({c})", "")
                                )[0]
                                names.append(name)
                            except (ValueError, TypeError):
                                names.append(f"UNKNOWN({c})")
                        op_name = ", ".join(names)
                else:
                    # Handle string representations of lists/sets first
                    cmd_str = str(cmd).strip()
                    if cmd_str.startswith(("[", "{")):
                        # String-encoded collection: "['5', '15']" or "['5' '15']"
                        cmd_cleaned = (
                            cmd_str.replace("[", "")
                            .replace("]", "")
                            .replace("{", "")
                            .replace("}", "")
                            .replace("'", "")
                            .replace('"', "")
                        )
                        # Split by comma or space (numpy arrays use spaces)
                        parts = (
                            cmd_cleaned.split(",")
                            if "," in cmd_cleaned
                            else cmd_cleaned.split()
                        )
                        # Translate ALL commands and join with comma
                        names = []
                        for part in parts:
                            c = part.strip()
                            if c:
                                try:
                                    cmd_int = int(c)
                                    name = SMB2_OP_NAME_DESC.get(
                                        cmd_int, (f"UNKNOWN({c})", "")
                                    )[0]
                                    names.append(name)
                                except (ValueError, TypeError):
                                    names.append(f"UNKNOWN({c})")
                        op_name = ", ".join(names) if names else "UNKNOWN"
                    else:
                        # Regular string: clean and parse
                        cmd_cleaned = (
                            cmd_str.split(",")[0]
                            .strip()
                            .replace("{", "")
                            .replace("}", "")
                            .replace("[", "")
                            .replace("]", "")
                            .replace("'", "")
                        )
                        # Parse as integer directly, avoiding masked float conversion
                        # Handle hex strings (0x...) and decimal strings
                        if cmd_cleaned.startswith("0x"):
                            cmd_int = int(cmd_cleaned, 16)
                        elif "." in cmd_cleaned:
                            # Only use float conversion if there's a decimal point
                            cmd_int = int(float(cmd_cleaned))
                        else:
                            cmd_int = int(cmd_cleaned)
                        op_name = SMB2_OP_NAME_DESC.get(
                            cmd_int, (f"UNKNOWN({cmd})", "")
                        )[0]
            except (ValueError, TypeError) as e:
                logger.debug(f"Error translating command {cmd}: {e}")
                op_name = f"UNKNOWN({cmd})" if cmd is not None else "UNKNOWN"

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
        self, selected_fields: list[str] | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        """Get operations using optimized vectorized processing."""
        return self.get_operations_vectorized(selected_fields, limit)

    def get_session_frames(self) -> pd.DataFrame | None:
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

    def get_session_summary(self) -> dict[str, Any]:
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
                        # Try to convert each element, handling various formats
                        cmd_ints = []
                        for c in cmd_str:
                            with contextlib.suppress(ValueError, TypeError):
                                cmd_ints.append(int(c))
                    else:
                        # Try direct int conversion instead of isdigit() check
                        # isdigit() fails for "-1", "0x10", "1.0" which int() can handle
                        try:
                            cmd_ints = [int(cmd_str)]
                        except (ValueError, TypeError):
                            cmd_ints = []

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
_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get the global session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


# Convenience functions for backward compatibility
def load_capture() -> str | None:
    """Load capture from configuration."""
    return get_session_manager().load_capture_path()


def get_output_dir(capture_path: str) -> str | None:
    """Get output directory for capture."""
    return get_session_manager().get_output_directory(capture_path)


def list_session_files(output_dir: str) -> list[str]:
    """List session files in directory."""
    return get_session_manager().list_session_files(output_dir)


def load_and_summarize_session(capture_path: str, session_file: str) -> tuple:
    """Load and summarize a session."""
    return get_session_manager().load_and_summarize_session(capture_path, session_file)


def update_operations(
    capture_path: str,
    session_file: str,
    selected_file: str | None = None,
    selected_fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Update operations for session."""
    return get_session_manager().update_operations(
        capture_path, session_file, selected_file, selected_fields
    )


def get_operations() -> list[dict[str, Any]]:
    """Get current operations."""
    return get_session_manager().get_operations()


def get_session_frames() -> pd.DataFrame | None:
    """Get current session frames."""
    return get_session_manager().get_session_frames()
