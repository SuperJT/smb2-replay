"""
PCAP Ingestion and Session Extraction Module.
Handles PCAP file ingestion and extracts SMB2 sessions for analysis.
"""

import os
import time
import traceback
import json
import psutil
from collections import OrderedDict
from typing import Dict, List, Optional, Callable, Any
import pandas as pd
import pyarrow.parquet as pq

from .config import get_config, get_logger
from .constants import check_tshark_availability, get_all_fields, FIELD_MAPPINGS, CRITICAL_FIELDS
from .tshark_processor import (
    build_tshark_command, process_tshark_output, save_to_parquet, 
    get_packet_count, validate_pcap_file, create_session_directory
)

logger = get_logger()


def normalize_sesid(sesid_str) -> set[str]:
    """Normalize smb2.sesid values, handling lists and commas, returns set[str]."""
    logger.debug(f"Normalizing sesid: {str(sesid_str)[:200]}")
    try:
        if pd.isna(sesid_str) or not sesid_str:
            return set()
        if isinstance(sesid_str, (list, set)):
            sesids = {item.strip() for item in sesid_str if item and item != "0x0000000000000000"}
        else:
            sesids = {item.strip() for item in str(sesid_str).split(',') if item and item != "0x0000000000000000"}
        return sesids
    except Exception as e:
        logger.critical(f"Error in normalize_sesid: {str(e)}\n{traceback.format_exc()}")
        return set()


def normalize_cmd(cmd_str) -> set[str]:
    """Normalize smb2.cmd values, handling lists and commas, returns set[str]."""
    logger.debug(f"Normalizing cmd: {str(cmd_str)[:200]}")
    try:
        if pd.isna(cmd_str).any() if isinstance(cmd_str, (list, pd.Series, set)) else pd.isna(cmd_str):
            return set()
        if not cmd_str:
            return set()
        if isinstance(cmd_str, (list, set)):
            return {item.strip() for item in cmd_str if item}
        return {item.strip() for item in str(cmd_str).split(',') if item}
    except Exception as e:
        logger.critical(f"Error in normalize_cmd: {str(e)}\n{traceback.format_exc()}")
        return set()


def save_session_metadata(case_number: str, trace_name: str, sessions: Dict[str, pd.DataFrame], 
                         output_dir: str):
    """Save session metadata to JSON.
    
    Args:
        case_number: Case number
        trace_name: Trace name  
        sessions: Dictionary of session DataFrames
        output_dir: Output directory path
    """
    logger.info(f"Saving session metadata to {output_dir}")
    
    try:
        metadata = {
            "case_number": case_number,
            "trace_name": trace_name,
            "session_count": len(sessions),
            "session_details": {
                sesid: {"frame_count": len(df), "columns": len(df.columns)} 
                for sesid, df in sessions.items()
            }
        }
        
        metadata_path = os.path.join(output_dir, "session_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved session metadata to {metadata_path}")
        
    except Exception as e:
        logger.critical(f"Error in save_session_metadata: {str(e)}\n{traceback.format_exc()}")
        raise


def extract_unique_sessions(df: pd.DataFrame) -> List[str]:
    """Extract unique session IDs from DataFrame.
    
    Args:
        df: DataFrame with SMB2 data
        
    Returns:
        List of unique session IDs
    """
    logger.info(f"Extracting unique session IDs from {len(df)} rows")
    
    try:
        unique_sesids = df['smb2.sesid'].apply(normalize_sesid).explode().unique()
        unique_sesids = [s for s in unique_sesids if s and str(s).lower() != 'nan']
        
        logger.info(f"Found {len(unique_sesids)} unique session IDs")
        return unique_sesids
        
    except Exception as e:
        logger.critical(f"Error extracting session IDs: {e}")
        raise


def extract_sessions_from_dataframe(df: pd.DataFrame, unique_sesids: List[str], 
                                   status_callback: Optional[Callable] = None) -> Dict[str, pd.DataFrame]:
    """Extract individual sessions from main DataFrame.
    
    Args:
        df: Main DataFrame with all SMB2 data
        unique_sesids: List of unique session IDs
        status_callback: Optional callback for status updates
        
    Returns:
        Dictionary mapping session IDs to DataFrames
    """
    logger.info(f"Extracting {len(unique_sesids)} sessions")
    
    sessions = {}
    
    for i, sesid in enumerate(unique_sesids, 1):
        logger.debug(f"Processing session {i}/{len(unique_sesids)} - sesid: {sesid}")
        
        if status_callback:
            status_callback(f"Processing session {i}/{len(unique_sesids)} - sesid: {sesid}")
        
        # Filter frames for this session
        sesid_filter = df['smb2.sesid'].apply(lambda x: sesid in normalize_sesid(x))
        session_df = df[sesid_filter].copy()
        
        if not session_df.empty:
            # Normalize fields for this session
            session_df['smb2.cmd'] = session_df['smb2.cmd'].apply(normalize_cmd)
            session_df['smb2.filename'] = session_df['smb2.filename'].apply(
                lambda x: ','.join(x) if isinstance(x, list) else x
            )
            session_df['smb2.sesid'] = session_df['smb2.sesid'].apply(normalize_sesid)
            
            sessions[sesid] = session_df
            logger.debug(f"Processed session {sesid} with {len(session_df)} frames")
        else:
            logger.warning(f"No frames found for session {sesid}")
    
    logger.info(f"Extracted {len(sessions)} sessions")
    return sessions


def run_ingestion(capture_path: Optional[str] = None, reassembly_enabled: bool = False, 
                 force_reingest: bool = False, verbose: bool = False, 
                 status_callback: Optional[Callable] = None) -> Optional[Dict[str, Any]]:
    """Orchestrate PCAP ingestion and session extraction.
    
    Args:
        capture_path: Path to PCAP file
        reassembly_enabled: Enable TCP reassembly
        force_reingest: Force re-ingestion
        verbose: Enable verbose logging
        status_callback: Optional callback for status updates
        
    Returns:
        Dictionary with full DataFrame and sessions, or None if failed
    """
    logger.info(f"Starting ingestion with capture_path: {capture_path}, "
                f"reassembly_enabled: {reassembly_enabled}, force_reingest: {force_reingest}, "
                f"verbose: {verbose}")
    
    # Default status callback
    if status_callback is None:
        status_callback = lambda msg: logger.info(f"Status: {msg}")
    
    try:
        config = get_config()
        
        # Load capture_path from config if None
        if capture_path is None:
            capture_path = config.get_capture_path()
        
        if not capture_path:
            logger.critical("No valid capture path available for ingestion")
            status_callback("Critical: No valid capture path available for ingestion")
            return None
        
        capture_path = os.path.abspath(capture_path)
        trace_name = os.path.basename(capture_path).split('.')[0]
        
        logger.info(f"Validating PCAP: {capture_path}")
        status_callback(f"Starting ingestion for {trace_name}")
        
        # Validate PCAP file
        if not validate_pcap_file(capture_path):
            status_callback(f"Error - PCAP file invalid or corrupt")
            return None
        
        # Check tshark availability
        if not check_tshark_availability():
            logger.critical("Local tshark is not available")
            status_callback("Error - Local tshark is not available")
            return None
        
        # Get packet count and set limits
        packet_count = get_packet_count(capture_path)
        packet_limit = 10000 if packet_count is not None and packet_count > 10000 else None
        
        logger.info(f"Packet limit set to: {packet_limit if packet_limit is not None else 'None (full capture)'}")
        status_callback(f"Packet limit set to: {packet_limit if packet_limit is not None else 'None (full capture)'}")
        
        # Extract case number from path
        parts = capture_path.split(os.sep)
        case_number = "local_case"  # Default for local development
        if 'cases' in parts:
            cases_index = parts.index('cases')
            if cases_index + 1 < len(parts):
                case_number = parts[cases_index + 1]
        
        logger.info(f"Ingesting {trace_name} for case {case_number}")
        status_callback(f"Ingesting {trace_name} for case {case_number}")
        
        # Prepare fields for extraction
        base_fields = [
            "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "smb2.sesid", 
            "smb2.cmd", "smb2.filename", "smb2.tid", "smb2.nt_status", "smb2.msg_id"
        ]
        
        additional_fields = get_all_fields()
        if "smb2.ioctl.function" not in additional_fields:
            additional_fields.append("smb2.ioctl.function")
        
        fields = list(OrderedDict.fromkeys(base_fields + additional_fields))
        
        logger.info(f"Using {len(fields)} fields for tshark extraction")
        status_callback(f"Using {len(fields)} fields for tshark extraction")
        
        # Build tshark command
        cmd, used_fields = build_tshark_command(
            capture_path, fields, reassembly=reassembly_enabled, 
            packet_limit=packet_limit, verbose=verbose
        )
        
        logger.debug(f"Full tshark command: {' '.join(cmd)[:400]}...")
        status_callback(f"Full tshark command: {' '.join(cmd)[:400]}...")
        
        # Process tshark output
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
        
        logger.info(f"Processed {len(df)} frames")
        status_callback(f"Processed {len(df)} frames")
        
        # Extract unique sessions
        try:
            unique_sesids = extract_unique_sessions(df)
            status_callback(f"Found {len(unique_sesids)} unique session IDs")
        except Exception as e:
            logger.critical(f"Error extracting session IDs: {e}")
            status_callback(f"Error extracting session IDs: {e}")
            return None
        
        # Extract sessions
        logger.info(f"Extracting {len(unique_sesids)} sessions")
        status_callback(f"Extracting {len(unique_sesids)} sessions")
        
        sessions = extract_sessions_from_dataframe(df, unique_sesids, status_callback)
        
        logger.info(f"Extracted {len(sessions)} sessions")
        status_callback(f"Extracted {len(sessions)} sessions")
        
        # Create output directory
        output_dir = create_session_directory(case_number, trace_name, force_reingest)
        if output_dir is None:
            logger.critical(f"Failed to create output directory for {trace_name}")
            status_callback(f"Error - Failed to create output directory for {trace_name}")
            return None
        
        logger.info(f"Output directory: {output_dir}")
        status_callback(f"Output directory: {output_dir}")
        
        # Save data to Parquet files
        parquet_path = os.path.join(output_dir, "tshark_output_full.parquet")
        
        try:
            # Check available memory
            if psutil.virtual_memory().available < 512 * 1024**2:
                logger.warning("Low available memory before saving Parquet files")
                status_callback("Warning: Low available memory before saving Parquet files")
            
            # Save full dataset
            save_to_parquet(df, parquet_path)
            logger.info(f"Saved full data to {parquet_path}")
            status_callback(f"Saved full data to {parquet_path}")
            
            # Save individual sessions
            for sesid, session_df in sessions.items():
                session_parquet = os.path.join(output_dir, f"smb2_session_{sesid}.parquet")
                save_to_parquet(session_df, session_parquet)
                logger.info(f"Saved session {sesid} to {session_parquet}")
                status_callback(f"Saved session {sesid} to {session_parquet}")
            
            # Save metadata
            save_session_metadata(case_number, trace_name, sessions, output_dir)
            logger.info("Session metadata saved")
            
        except Exception as e:
            logger.critical(f"Error saving sessions or metadata: {str(e)}")
            status_callback(f"Error - Failed to save sessions or metadata: {str(e)}")
            return None
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        logger.info(f"Ingestion completed in {elapsed_time:.2f}s")
        status_callback(f"Ingestion completed in {elapsed_time:.2f}s")
        
        # Return result
        result = {"full_df": df, "sessions": sessions}
        logger.info(f"Ingestion result: {list(result.get('sessions', {}).keys())}")
        return result
        
    except Exception as e:
        logger.critical(f"Error in run_ingestion: {e}\n{traceback.format_exc()}")
        if status_callback:
            status_callback(f"Error in run_ingestion: {str(e)}")
        return None


def load_ingested_data(case_number: str, trace_name: str) -> Optional[Dict[str, Any]]:
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
        output_dir = create_session_directory(case_number, trace_name, force_reingest=False)
        
        # Load full dataset
        parquet_path = os.path.join(output_dir, "tshark_output_full.parquet")
        if not os.path.exists(parquet_path):
            logger.warning(f"Full dataset not found at {parquet_path}")
            return None
        
        full_df = pq.read_table(parquet_path).to_pandas()
        logger.info(f"Loaded full dataset with {len(full_df)} frames")
        
        # Load session metadata
        metadata_path = os.path.join(output_dir, "session_metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            logger.info(f"Loaded metadata for {metadata['session_count']} sessions")
        else:
            logger.warning(f"Session metadata not found at {metadata_path}")
            metadata = {}
        
        # Load individual sessions
        sessions = {}
        session_files = [f for f in os.listdir(output_dir) if f.startswith('smb2_session_') and f.endswith('.parquet')]
        
        for session_file in session_files:
            sesid = session_file.replace('smb2_session_', '').replace('.parquet', '')
            session_path = os.path.join(output_dir, session_file)
            
            try:
                session_df = pq.read_table(session_path).to_pandas()
                sessions[sesid] = session_df
                logger.debug(f"Loaded session {sesid} with {len(session_df)} frames")
            except Exception as e:
                logger.warning(f"Error loading session {sesid}: {e}")
        
        logger.info(f"Loaded {len(sessions)} sessions")
        
        return {
            "full_df": full_df,
            "sessions": sessions,
            "metadata": metadata
        }
        
    except Exception as e:
        logger.critical(f"Error in load_ingested_data: {e}\n{traceback.format_exc()}")
        return None


def validate_ingested_data(data: Dict[str, Any]) -> bool:
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
        missing_fields = [field for field in CRITICAL_FIELDS if field not in full_df.columns]
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
            if 'smb2.sesid' not in session_df.columns:
                logger.error(f"Session {sesid} missing smb2.sesid field")
                return False
        
        logger.info("Data validation passed")
        return True
        
    except Exception as e:
        logger.critical(f"Error in validate_ingested_data: {e}\n{traceback.format_exc()}")
        return False 