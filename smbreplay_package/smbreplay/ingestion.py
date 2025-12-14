"""
PCAP Ingestion and Session Extraction Module.
Handles PCAP file ingestion and extracts SMB2 sessions for analysis.
Optimized for performance and memory efficiency.
"""

import asyncio
import gc
import json
import os
import time
import traceback
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import psutil
import pyarrow.parquet as pq

from .config import get_config, get_logger
from .constants import (
    CRITICAL_FIELDS,
    check_tshark_availability,
    get_all_fields,
)
from .database import get_database_client
from .tshark_processor import (
    build_tshark_command,
    create_session_directory,
    get_packet_count,
    process_tshark_output,
    save_to_parquet,
    validate_pcap_file,
)

logger = get_logger()

# Performance optimization constants
SESSION_CHUNK_SIZE = 1000  # Process sessions in chunks


def normalize_sesid_vectorized(sesid_series: pd.Series) -> pd.Series:
    """Vectorized normalization of smb2.sesid values.

    Args:
        sesid_series: Pandas Series with sesid values

    Returns:
        Series with normalized sesid sets
    """
    logger.debug(f"Normalizing {len(sesid_series)} sesid values vectorized")

    def normalize_single_sesid(sesid_str):
        """Normalize a single sesid value."""
        try:
            if pd.isna(sesid_str) or not sesid_str:
                return set()

            if isinstance(sesid_str, (list, set)):
                sesids = {
                    item.strip()
                    for item in sesid_str
                    if item and item != "0x0000000000000000"
                }
            else:
                sesids = {
                    item.strip()
                    for item in str(sesid_str).split(",")
                    if item and item != "0x0000000000000000"
                }

            return sesids
        except Exception as e:
            logger.debug(f"Error normalizing sesid {sesid_str}: {e}")
            return set()

    return sesid_series.apply(normalize_single_sesid)


def normalize_cmd_vectorized(cmd_series: pd.Series) -> pd.Series:
    """Vectorized normalization of smb2.cmd values.

    Args:
        cmd_series: Pandas Series with cmd values

    Returns:
        Series with normalized cmd sets
    """
    logger.debug(f"Normalizing {len(cmd_series)} cmd values vectorized")

    def normalize_single_cmd(cmd_str):
        """Normalize a single cmd value."""
        try:
            if pd.isna(cmd_str) or not cmd_str:
                return set()

            if isinstance(cmd_str, (list, set)):
                return {item.strip() for item in cmd_str if item}

            return {item.strip() for item in str(cmd_str).split(",") if item}
        except Exception as e:
            logger.debug(f"Error normalizing cmd {cmd_str}: {e}")
            return set()

    return cmd_series.apply(normalize_single_cmd)


def extract_unique_sessions_optimized(df: pd.DataFrame) -> list[str]:
    """Extract unique session IDs from DataFrame using vectorized operations.

    Args:
        df: DataFrame with SMB2 data

    Returns:
        List of unique session IDs
    """
    logger.info(f"Extracting unique sessions from DataFrame with {len(df)} rows")

    try:
        if "smb2.sesid" not in df.columns:
            logger.warning("No smb2.sesid column found in DataFrame")
            return []

        # Use vectorized operations to extract all sesids
        sesid_series = df["smb2.sesid"].dropna()
        if sesid_series.empty:
            logger.warning("No valid smb2.sesid values found")
            return []

        # Flatten all sesids efficiently
        all_sesids = []
        for sesid_str in sesid_series:
            if pd.isna(sesid_str) or not sesid_str:
                continue

            if isinstance(sesid_str, list):
                all_sesids.extend(
                    [s.strip() for s in sesid_str if s and s != "0x0000000000000000"]
                )
            else:
                all_sesids.extend(
                    [
                        s.strip()
                        for s in str(sesid_str).split(",")
                        if s and s != "0x0000000000000000"
                    ]
                )

        # Get unique values while preserving order
        unique_sesids = list(dict.fromkeys(all_sesids))

        logger.info(f"Found {len(unique_sesids)} unique session IDs")
        return unique_sesids

    except Exception as e:
        logger.critical(f"Error extracting unique sessions: {e}")
        return []


def extract_sessions_from_dataframe_optimized(
    df: pd.DataFrame,
    unique_sesids: list[str],
    status_callback: Callable | None = None,
) -> dict[str, pd.DataFrame]:
    """Extract individual sessions from main DataFrame using optimized operations.

    Args:
        df: Main DataFrame with all SMB2 data
        unique_sesids: List of unique session IDs
        status_callback: Optional callback for status updates

    Returns:
        Dictionary mapping session IDs to DataFrames
    """
    logger.info(f"Extracting {len(unique_sesids)} sessions with optimized processing")

    sessions = {}

    # Pre-normalize sesid column for efficient filtering
    logger.debug("Pre-normalizing sesid column for efficient filtering")
    df_sesids_normalized = normalize_sesid_vectorized(df["smb2.sesid"])

    for i, sesid in enumerate(unique_sesids, 1):
        logger.debug(f"Processing session {i}/{len(unique_sesids)} - sesid: {sesid}")

        if status_callback:
            status_callback(
                f"Processing session {i}/{len(unique_sesids)} - sesid: {sesid}"
            )

        # Efficient boolean indexing
        # Use 'x is not None' instead of 'if x' to handle empty sets correctly
        # (empty set() is falsy but still valid for 'in' check)
        # Use default argument s=sesid to capture loop variable by value
        session_mask = df_sesids_normalized.apply(
            lambda x, s=sesid: s in x if x is not None else False
        )
        session_df = df[session_mask].copy()

        if not session_df.empty:
            # Batch process normalizations for better performance
            session_df["smb2.cmd"] = normalize_cmd_vectorized(session_df["smb2.cmd"])

            # Optimize filename normalization
            if "smb2.filename" in session_df.columns:
                session_df["smb2.filename"] = session_df["smb2.filename"].apply(
                    lambda x: (
                        ",".join(x) if isinstance(x, list) else str(x) if x else ""
                    )
                )

            # Keep normalized sesids
            session_df["smb2.sesid"] = df_sesids_normalized[session_mask]

            sessions[sesid] = session_df
            logger.debug(f"Processed session {sesid} with {len(session_df)} frames")

            # Memory management for large sessions
            if len(session_df) > 5000:
                gc.collect()
        else:
            logger.warning(f"No frames found for session {sesid}")

    logger.info(f"Extracted {len(sessions)} sessions")
    return sessions


def _convert_numpy_types(obj):
    """Convert numpy types to native Python types for JSON serialization."""
    import numpy as np

    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: _convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_convert_numpy_types(item) for item in obj]
    else:
        return obj


def save_session_metadata(
    case_number: str,
    trace_name: str,
    sessions: dict[str, pd.DataFrame],
    output_dir: str,
):
    """Save session metadata to JSON with performance stats.

    Args:
        case_number: Case number
        trace_name: Trace name
        sessions: Dictionary of session DataFrames
        output_dir: Output directory path
    """
    logger.info(f"Saving session metadata to {output_dir}")

    try:
        # Calculate memory usage for each session
        session_details = {}
        total_memory = 0

        for sesid, df in sessions.items():
            memory_mb = df.memory_usage(deep=True).sum() / 1024**2
            total_memory += memory_mb

            # Calculate unique commands safely
            unique_commands = 0
            if "smb2.cmd" in df.columns:
                try:
                    unique_commands = int(df["smb2.cmd"].apply(len).sum())
                except (TypeError, ValueError):
                    unique_commands = 0

            session_details[sesid] = {
                "frame_count": len(df),
                "columns": len(df.columns),
                "memory_mb": round(memory_mb, 2),
                "unique_commands": unique_commands,
            }

        metadata = {
            "case_number": case_number,
            "trace_name": trace_name,
            "session_count": len(sessions),
            "total_memory_mb": round(total_memory, 2),
            "session_details": session_details,
            "optimization_applied": True,
            "extraction_timestamp": time.time(),
        }

        # Convert any numpy types to native Python types
        metadata = _convert_numpy_types(metadata)

        metadata_path = Path(output_dir) / "session_metadata.json"
        with metadata_path.open("w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(
            f"Saved session metadata to {metadata_path} (Total memory: {total_memory:.2f}MB)"
        )

    except Exception as e:
        logger.critical(
            f"Error in save_session_metadata: {e!s}\n{traceback.format_exc()}"
        )
        raise


async def save_sessions_to_database(
    case_number: str,
    trace_name: str,
    capture_path: str,
    packet_count: int,
    file_size: int,
    sessions: dict[str, pd.DataFrame],
    status_callback: Callable | None = None,
) -> None:
    """Save trace and session data to PostgreSQL + S3.

    Frame data is stored in S3 as Parquet files.
    Metadata and S3 object keys are stored in PostgreSQL.

    Args:
        case_number: Case number
        trace_name: Trace name
        capture_path: Full path to capture file
        packet_count: Number of packets in trace
        file_size: File size in bytes
        sessions: Dictionary of session DataFrames
        status_callback: Optional callback for status updates
    """
    from .frame_storage import get_frame_storage

    logger.info(
        f"Saving {len(sessions)} sessions to database+S3 for {case_number}/{trace_name}"
    )

    uploaded_keys: list[str] = []  # Track uploaded S3 objects for cleanup on failure

    try:
        db = get_database_client()
        frame_storage = get_frame_storage()

        # Create or update trace record
        trace_id = await db.create_or_update_trace(
            case_number=case_number,
            trace_name=trace_name,
            capture_file_path=capture_path,
            packet_count=packet_count,
            file_size=file_size,
            status="INGESTING",
            metadata={"session_count": len(sessions)},
        )

        logger.info(f"Created/updated trace {trace_id} in database")
        if status_callback:
            status_callback(f"Saving {len(sessions)} sessions to S3...")

        # Save individual sessions
        for i, (sesid, session_df) in enumerate(sessions.items(), 1):
            # Calculate unique commands
            unique_commands = 0
            if "smb2.cmd" in session_df.columns:
                try:
                    unique_commands = int(session_df["smb2.cmd"].apply(len).sum())
                except (TypeError, ValueError):
                    unique_commands = 0

            # Upload frames to S3
            object_key, size_bytes = frame_storage.save_frames(
                case_id=case_number,
                trace_name=trace_name,
                session_id=sesid,
                frames_df=session_df,
            )
            uploaded_keys.append(object_key)

            # Calculate memory usage
            frame_count = len(session_df)
            memory_mb = session_df.memory_usage(deep=True).sum() / 1024**2

            # Store metadata in database (no frame data)
            await db.create_session(
                trace_id=trace_id,
                session_id=sesid,
                frame_count=frame_count,
                unique_commands=unique_commands,
                memory_mb=memory_mb,
                frames_object_key=object_key,
                frames_size_bytes=size_bytes,
            )

            if i % 10 == 0 or i == len(sessions):
                logger.info(f"Saved {i}/{len(sessions)} sessions to S3+database")
                if status_callback:
                    status_callback(f"Saved {i}/{len(sessions)} sessions")

        # Mark trace as completed
        await db.update_trace_status(
            trace_id=trace_id, status="COMPLETED", ingested_at=datetime.now()
        )

        logger.info(f"Successfully saved all {len(sessions)} sessions to S3+database")

    except Exception as e:
        logger.error(f"Error saving to database/S3: {e!s}\n{traceback.format_exc()}")

        # Cleanup: try to delete any uploaded S3 objects on failure
        if uploaded_keys:
            logger.info(f"Cleaning up {len(uploaded_keys)} uploaded S3 objects...")
            try:
                frame_storage = get_frame_storage()
                for key in uploaded_keys:
                    frame_storage.delete_frames(key)
            except Exception as cleanup_e:
                logger.error(f"Failed to cleanup S3 objects: {cleanup_e}")

        # Try to mark trace as failed
        try:
            if "trace_id" in locals():
                db = get_database_client()
                await db.update_trace_status(
                    trace_id=trace_id,
                    status="FAILED",
                    error_message=str(e),
                )
        except Exception as inner_e:
            logger.error(f"Failed to update trace status: {inner_e}")

        # Re-raise the exception
        raise


# Maintain backward compatibility while using optimized functions
def normalize_sesid(sesid_str) -> list[str]:
    """Normalize smb2.sesid values, handling lists and commas, returns list[str].

    Returns a sorted list (not set) for JSON/Parquet serialization compatibility.
    """
    logger.debug(f"Normalizing sesid: {str(sesid_str)[:200]}")
    try:
        if pd.isna(sesid_str) or not sesid_str:
            return []
        if isinstance(sesid_str, (list, set)):
            sesids = {
                item.strip()
                for item in sesid_str
                if item and item != "0x0000000000000000"
            }
        else:
            sesids = {
                item.strip()
                for item in str(sesid_str).split(",")
                if item and item != "0x0000000000000000"
            }
        return sorted(sesids)  # Convert to sorted list for serialization
    except Exception as e:
        logger.critical(f"Error in normalize_sesid: {e!s}\n{traceback.format_exc()}")
        return []


def normalize_cmd(cmd_str) -> list[str]:
    """Normalize smb2.cmd values, handling lists and commas, returns list[str].

    Returns a sorted list (not set) for JSON/Parquet serialization compatibility.
    """
    logger.debug(f"Normalizing cmd: {str(cmd_str)[:200]}")
    try:
        # Handle None and NaN values
        if cmd_str is None:
            return []
        # For pd.Series, use .any() to check if any values are NA
        if isinstance(cmd_str, pd.Series):
            if pd.isna(cmd_str).any():
                return []
        # For lists, check each element
        elif isinstance(cmd_str, list):
            if all(pd.isna(item) for item in cmd_str):
                return []
        # For sets, convert to list first (pd.isna doesn't handle sets well)
        elif isinstance(cmd_str, set):
            if not cmd_str:  # Empty set
                return []
            # Filter out None/NaN values from the set
            valid_items = {
                item
                for item in cmd_str
                if item is not None and not (isinstance(item, float) and pd.isna(item))
            }
            return sorted(str(item).strip() for item in valid_items if item)
        # For scalar values
        elif pd.isna(cmd_str):
            return []

        if not cmd_str:
            return []
        if isinstance(cmd_str, (list, set)):
            return sorted(str(item).strip() for item in cmd_str if item)
        return sorted(item.strip() for item in str(cmd_str).split(",") if item)
    except Exception as e:
        logger.critical(f"Error in normalize_cmd: {e!s}\n{traceback.format_exc()}")
        return []


def extract_unique_sessions(df: pd.DataFrame) -> list[str]:
    """Extract unique session IDs from DataFrame."""
    return extract_unique_sessions_optimized(df)


def extract_sessions_from_dataframe(
    df: pd.DataFrame,
    unique_sesids: list[str],
    status_callback: Callable | None = None,
) -> dict[str, pd.DataFrame]:
    """Extract individual sessions from main DataFrame."""
    return extract_sessions_from_dataframe_optimized(df, unique_sesids, status_callback)


def run_ingestion(
    capture_path: str | None = None,
    reassembly_enabled: bool = False,
    force_reingest: bool = False,
    verbose: bool = False,
    status_callback: Callable | None = None,
) -> dict[str, Any] | None:
    """Orchestrate PCAP ingestion and session extraction with performance optimizations.

    Args:
        capture_path: Path to PCAP file
        reassembly_enabled: Enable TCP reassembly
        force_reingest: Force re-ingestion
        verbose: Enable verbose logging
        status_callback: Optional callback for status updates

    Returns:
        Dictionary with full DataFrame and sessions, or None if failed
    """
    logger.info(
        f"Starting optimized ingestion with capture_path: {capture_path}, "
        f"reassembly_enabled: {reassembly_enabled}, force_reingest: {force_reingest}, "
        f"verbose: {verbose}"
    )

    # Default status callback
    if status_callback is None:

        def default_status_callback(msg):
            logger.info(f"Status: {msg}")

        status_callback = default_status_callback

    try:
        config = get_config()

        # Load capture_path from config if None
        if capture_path is None:
            capture_path = config.get_capture_path()

        if not capture_path:
            logger.critical("No valid capture path available for ingestion")
            status_callback("Critical: No valid capture path available for ingestion")
            return None

        capture_path_obj = Path(capture_path)
        if not capture_path_obj.exists():
            logger.critical(f"Capture file not found: {capture_path}")
            if status_callback is not None:
                status_callback(f"Error - Capture file not found: {capture_path}")
            return None

        capture_path = str(capture_path_obj.resolve())
        trace_name = capture_path_obj.stem

        logger.info(f"Validating PCAP: {capture_path}")
        status_callback(f"Starting optimized ingestion for {trace_name}")

        # Monitor initial memory
        initial_memory = psutil.Process().memory_info().rss / 1024**2
        logger.info(f"Initial memory usage: {initial_memory:.2f} MB")

        # Validate PCAP file
        if not validate_pcap_file(capture_path):
            status_callback("Error - PCAP file invalid or corrupt")
            return None

        # Check tshark availability
        if not check_tshark_availability():
            logger.critical("Local tshark is not available")
            status_callback("Error - Local tshark is not available")
            return None

        # Get packet count and set limits for performance
        packet_count = get_packet_count(capture_path)
        packet_limit = (
            50000 if packet_count is not None and packet_count > 50000 else None
        )

        if packet_limit:
            logger.info(
                f"Performance optimization: Limiting to {packet_limit} packets (total: {packet_count})"
            )
            status_callback(
                f"Performance optimization: Processing first {packet_limit} packets"
            )

        # Extract case number from path
        # The case number is the first directory component after TRACES_FOLDER
        # e.g., /stingray/2010101010/smb-trace.pcapng -> case_number = "2010101010"
        case_number = "local_case"  # Default for local development
        traces_folder = get_config().get_traces_folder()

        # Normalize both paths for comparison (resolve symlinks, remove trailing slashes)
        norm_capture = Path(capture_path).resolve()
        norm_traces = Path(traces_folder).resolve()

        # Check if capture path is within traces folder
        try:
            relative_path = norm_capture.relative_to(norm_traces)
            parts = relative_path.parts
            if parts and parts[0]:
                case_number = parts[0]
        except ValueError:
            # Fallback: look for "cases" in path for backward compatibility
            parts = Path(capture_path).parts
            if "cases" in parts:
                cases_index = parts.index("cases")
                if cases_index + 1 < len(parts):
                    case_number = parts[cases_index + 1]

        logger.info(f"Ingesting {trace_name} for case {case_number}")
        status_callback(f"Ingesting {trace_name} for case {case_number}")

        # Prepare optimized field list
        base_fields = [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "smb2.sesid",
            "smb2.cmd",
            "smb2.filename",
            "smb2.tid",
            "smb2.nt_status",
            "smb2.msg_id",
        ]

        additional_fields = get_all_fields()
        if "smb2.ioctl.function" not in additional_fields:
            additional_fields.append("smb2.ioctl.function")

        fields = list(OrderedDict.fromkeys(base_fields + additional_fields))

        logger.info(f"Using {len(fields)} fields for optimized tshark extraction")
        status_callback(f"Using {len(fields)} fields for optimized extraction")

        # Build tshark command
        cmd, used_fields = build_tshark_command(
            capture_path,
            fields,
            reassembly=reassembly_enabled,
            packet_limit=packet_limit,
            verbose=verbose,
        )

        # Process tshark output with optimized processing
        start_time = time.time()

        try:
            df = process_tshark_output(cmd, used_fields)
        except Exception as e:
            logger.critical(f"Error during tshark processing: {e}")
            status_callback(f"Error during tshark processing: {e}")
            return None

        if df.empty:
            logger.critical("No data extracted from tshark output")
            status_callback("Error - No data extracted from tshark output")
            return None

        processing_memory = psutil.Process().memory_info().rss / 1024**2
        logger.info(f"Processed {len(df)} frames (Memory: {processing_memory:.2f} MB)")
        status_callback(f"Processed {len(df)} frames")

        # Extract unique sessions with optimization
        try:
            unique_sesids = extract_unique_sessions_optimized(df)
            status_callback(f"Found {len(unique_sesids)} unique session IDs")
        except Exception as e:
            logger.critical(f"Error extracting session IDs: {e}")
            status_callback(f"Error extracting session IDs: {e}")
            return None

        # Extract sessions with optimized processing
        logger.info(f"Extracting {len(unique_sesids)} sessions with optimization")
        status_callback(f"Extracting {len(unique_sesids)} sessions")

        sessions = extract_sessions_from_dataframe_optimized(
            df, unique_sesids, status_callback
        )

        extraction_memory = psutil.Process().memory_info().rss / 1024**2
        logger.info(
            f"Extracted {len(sessions)} sessions (Memory: {extraction_memory:.2f} MB)"
        )
        status_callback(f"Extracted {len(sessions)} sessions")

        # Create output directory
        output_dir = create_session_directory(case_number, trace_name, force_reingest)
        if output_dir is None:
            logger.critical(f"Failed to create output directory for {trace_name}")
            status_callback(
                f"Error - Failed to create output directory for {trace_name}"
            )
            return None

        logger.info(f"Output directory: {output_dir}")
        status_callback(f"Output directory: {output_dir}")

        # Determine storage strategy
        use_database = os.getenv("USE_DATABASE", "true").lower() == "true"

        try:
            if use_database:
                # Database-only mode: Skip Parquet, save directly to PostgreSQL
                logger.info("Database mode enabled - saving directly to PostgreSQL...")
                status_callback("Saving sessions to database...")

                try:
                    asyncio.run(
                        save_sessions_to_database(
                            case_number=case_number,
                            trace_name=trace_name,
                            capture_path=capture_path,
                            packet_count=packet_count,
                            file_size=Path(capture_path).stat().st_size,
                            sessions=sessions,
                            status_callback=status_callback,
                        )
                    )
                    logger.info("Successfully saved sessions to database")
                    status_callback("Successfully saved sessions to database")
                except Exception as db_error:
                    logger.error(f"Failed to save to database: {db_error}")
                    status_callback(
                        f"Error - Failed to save sessions to database: {db_error!s}"
                    )
                    raise  # Fail the ingestion if database save fails in database-only mode

            else:
                # Parquet-only mode: Save to Parquet files (legacy behavior)
                logger.info("Parquet mode enabled - saving to Parquet files...")
                parquet_path = str(Path(output_dir) / "tshark_output_full.parquet")

                # Monitor memory before saving
                available_memory = psutil.virtual_memory().available / 1024**2

                if available_memory < 512:
                    logger.warning(f"Low available memory: {available_memory:.2f}MB")
                    status_callback(
                        f"Warning: Low available memory: {available_memory:.2f}MB"
                    )
                    gc.collect()  # Force garbage collection

                # Save full dataset
                save_to_parquet(df, parquet_path)
                logger.info(f"Saved full data to {parquet_path}")
                status_callback(f"Saved full data to {parquet_path}")

                # Save individual sessions with progress tracking
                for i, (sesid, session_df) in enumerate(sessions.items(), 1):
                    session_parquet = str(
                        Path(output_dir) / f"smb2_session_{sesid}.parquet"
                    )
                    save_to_parquet(session_df, session_parquet)

                    if i % 10 == 0 or i == len(sessions):
                        logger.info(f"Saved {i}/{len(sessions)} sessions")
                        status_callback(f"Saved {i}/{len(sessions)} sessions")

                # Save enhanced metadata
                save_session_metadata(case_number, trace_name, sessions, output_dir)
                logger.info("Enhanced session metadata saved")

        except Exception as e:
            logger.critical(f"Error saving sessions or metadata: {e!s}")
            status_callback(f"Error - Failed to save sessions or metadata: {e!s}")
            return None

        # Calculate performance metrics
        elapsed_time = time.time() - start_time
        final_memory = psutil.Process().memory_info().rss / 1024**2
        memory_increase = final_memory - initial_memory

        logger.info(
            f"Optimized ingestion completed in {elapsed_time:.2f}s "
            f"(Memory increase: {memory_increase:.2f}MB)"
        )
        status_callback(f"Optimized ingestion completed in {elapsed_time:.2f}s")

        # Return result with performance metadata
        result = {
            "full_df": df,
            "sessions": sessions,
            "performance": {
                "processing_time": elapsed_time,
                "memory_increase_mb": memory_increase,
                "packets_processed": len(df),
                "sessions_extracted": len(sessions),
            },
        }

        logger.info(f"Ingestion result: {list(result.get('sessions', {}).keys())}")
        return result

    except Exception as e:
        logger.critical(f"Error in run_ingestion: {e}\n{traceback.format_exc()}")
        if status_callback is not None:
            status_callback(f"Error in run_ingestion: {e!s}")
        return None


def load_ingested_data(case_number: str, trace_name: str) -> dict[str, Any] | None:
    """Load previously ingested data from Parquet files.

    Args:
        case_number: Case number
        trace_name: Trace name

    Returns:
        Dictionary with full DataFrame and sessions, or None if failed
    """
    logger.info(f"Loading ingested data for case {case_number}, trace {trace_name}")

    try:
        # Get output directory
        output_dir = create_session_directory(
            case_number, trace_name, force_reingest=False
        )

        # Load full dataset
        output_dir_path = Path(output_dir)
        parquet_path = output_dir_path / "tshark_output_full.parquet"
        if not parquet_path.exists():
            logger.warning(f"Full dataset not found at {parquet_path}")
            return None

        full_df = pq.read_table(str(parquet_path)).to_pandas()
        logger.info(f"Loaded full dataset with {len(full_df)} frames")

        # Load session metadata
        metadata_path = output_dir_path / "session_metadata.json"
        if metadata_path.exists():
            with metadata_path.open() as f:
                metadata = json.load(f)
            logger.info(f"Loaded metadata for {metadata['session_count']} sessions")
        else:
            logger.warning(f"Session metadata not found at {metadata_path}")
            metadata = {}

        # Load individual sessions
        sessions = {}
        session_files = [
            f.name
            for f in output_dir_path.iterdir()
            if f.name.startswith("smb2_session_") and f.name.endswith(".parquet")
        ]

        for session_file in session_files:
            sesid = session_file.replace("smb2_session_", "").replace(".parquet", "")
            session_path = output_dir_path / session_file

            try:
                session_df = pq.read_table(session_path).to_pandas()
                sessions[sesid] = session_df
                logger.debug(f"Loaded session {sesid} with {len(session_df)} frames")
            except Exception as e:
                logger.warning(f"Error loading session {sesid}: {e}")

        logger.info(f"Loaded {len(sessions)} sessions")

        return {"full_df": full_df, "sessions": sessions, "metadata": metadata}

    except Exception as e:
        logger.critical(f"Error in load_ingested_data: {e}\n{traceback.format_exc()}")
        return None


def validate_ingested_data(data: dict[str, Any]) -> bool:
    """Validate ingested data for completeness and integrity.

    Args:
        data: Dictionary with ingested data

    Returns:
        True if data is valid, False otherwise
    """
    logger.info("Validating ingested data")

    try:
        if not data or "full_df" not in data or "sessions" not in data:
            logger.error("Missing required data components")
            return False

        full_df = data["full_df"]
        sessions = data["sessions"]

        # Check DataFrame structure
        if full_df.empty:
            logger.error("Full DataFrame is empty")
            return False

        # Check for critical fields
        missing_fields = [
            field for field in CRITICAL_FIELDS if field not in full_df.columns
        ]
        if missing_fields:
            logger.warning(f"Missing critical fields: {missing_fields}")

        # Check sessions
        if not sessions:
            logger.error("No sessions found")
            return False

        # Validate each session
        for sesid, session_df in sessions.items():
            if session_df.empty:
                logger.warning(f"Session {sesid} is empty")
                continue

            # Check session has required fields
            if "smb2.sesid" not in session_df.columns:
                logger.error(f"Session {sesid} missing smb2.sesid field")
                return False

        logger.info("Data validation passed")
        return True

    except Exception as e:
        logger.critical(
            f"Error in validate_ingested_data: {e}\n{traceback.format_exc()}"
        )
        return False
