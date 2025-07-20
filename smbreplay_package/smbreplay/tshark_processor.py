"""
TShark PCAP Processing Module.
Handles PCAP file processing using tshark for SMB2 protocol analysis.
Optimized for performance and memory efficiency.
"""

import os
import subprocess
import shlex
import traceback
import json
import psutil
import gc
from typing import List, Dict, Tuple, Any, Optional, Iterator
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import numpy as np

from .config import get_logger
from .constants import TSHARK_PATH, get_all_fields

logger = get_logger()

# Performance optimization constants
CHUNK_SIZE = 5000  # Process data in chunks to manage memory
MEMORY_THRESHOLD_MB = 512  # Memory threshold for warnings


def build_tshark_command(capture: str, fields: List[str], reassembly: bool = False, 
                        packet_limit: Optional[int] = None, log_level: str = "debug", 
                        temp_dir: str = "/tmp", verbose: bool = False) -> Tuple[List[str], List[str]]:
    """Construct local tshark command to process PCAP.
    
    Args:
        capture: Path to the PCAP file
        fields: List of fields to extract
        reassembly: Enable TCP reassembly
        packet_limit: Maximum number of packets to process
        log_level: Logging level (unused for standard tshark)
        temp_dir: Temporary directory (unused for standard tshark)
        verbose: Enable verbose output
        
    Returns:
        Tuple of (command_args, fields_used)
    """
    logger.info(f"Building local tshark command for capture: {capture}")
    
    tshark_args = [
        TSHARK_PATH,
        "-r", capture,
        "-Y", "smb2",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "header=y",
        "-E", "occurrence=a",
        "-q"
    ]
    
    if reassembly:
        tshark_args.append("-2")
        logger.debug("Enabled TCP reassembly with -2 flag")
    
    if packet_limit is not None:
        tshark_args.extend(["-c", str(packet_limit)])
        logger.debug(f"Set packet limit to {packet_limit}")
    
    if verbose:
        tshark_args.append("-V")
        logger.debug("Enabled verbose tshark output with -V flag")
    
    for field in fields:
        tshark_args.extend(["-e", field])
    
    logger.debug(f"Constructed local tshark command: {' '.join(tshark_args)[:400]}...")
    
    return tshark_args, fields


def extract_fields_vectorized(lines: List[str], fields: List[str]) -> List[Dict[str, Any]]:
    """Parse multiple tshark output lines efficiently using vectorized operations.
    
    Args:
        lines: List of raw tshark output lines
        fields: List of field names
        
    Returns:
        List of field dictionaries
    """
    logger.debug(f"Extracting fields from {len(lines)} lines vectorized...")
    
    records = []
    for line_num, line in enumerate(lines, 1):
        try:
            split_line = line.split("|")
            if not split_line or not split_line[0].strip() or len(split_line) < 5:
                continue
            
            if len(split_line) < len(fields):
                split_line.extend([""] * (len(fields) - len(split_line)))
            
            # Clean values efficiently
            cleaned_values = [value.split("\x02")[0] if value else "" for value in split_line[:len(fields)]]
            field_dict = dict(zip(fields, cleaned_values))
            
            # Extract key fields
            frame_number = field_dict.get("frame.number", "")
            try:
                frame = int(frame_number) if frame_number else line_num
            except (ValueError, TypeError):
                frame = line_num
            
            tcp_stream = field_dict.get("tcp.stream", "")
            try:
                stream = int(tcp_stream) if tcp_stream else -1
            except (ValueError, TypeError):
                stream = -1
            
            ip_src = field_dict.get("ip.src", "")
            ip_dst = field_dict.get("ip.dst", "")
            sesid = field_dict.get("smb2.sesid", "")
            
            # Correct frame number
            field_dict['frame.number'] = str(frame)
            
            record = {
                "frame.number": frame,
                "tcp.stream": stream,
                "ip.src": ip_src,
                "ip.dst": ip_dst,
                "smb2.sesid": sesid,
                **field_dict
            }
            records.append(record)
            
        except Exception as e:
            logger.debug(f"Skipping line {line_num} due to error: {e}")
            continue
    
    return records


def process_tshark_output_chunked(cmd: List[str], fields: List[str]) -> pd.DataFrame:
    """Process tshark output in chunks for better memory management.
    
    Args:
        cmd: Tshark command arguments
        fields: List of field names
        
    Returns:
        DataFrame with extracted SMB2 data
    """
    logger.info(f"Processing tshark output with chunked processing: {' '.join(cmd)[:200]}...")
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Process output in chunks
        chunk_data = []
        all_data = []
        line_count = 0
        skip_count = 0
        header_skipped = False
        
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
                
            if not header_skipped:
                header_fields = line.split("|")
                if header_fields != fields[:len(header_fields)]:
                    logger.warning(f"Header fields mismatch! Expected: {fields[:10]}, Got: {header_fields[:10]}")
                logger.debug(f"Header row: {line[:200]}...")
                header_skipped = True
                continue
            
            chunk_data.append(line)
            line_count += 1
            
            # Process chunk when it reaches the chunk size
            if len(chunk_data) >= CHUNK_SIZE:
                records = extract_fields_vectorized(chunk_data, fields)
                all_data.extend(records)
                chunk_data = []
                
                # Memory management
                current_memory = psutil.Process().memory_info().rss / 1024**2
                if line_count % (CHUNK_SIZE * 2) == 0:
                    logger.info(f"Processed {line_count} lines, memory usage: {current_memory:.2f} MB")
                    
                if current_memory > MEMORY_THRESHOLD_MB * 2:
                    logger.warning(f"High memory usage: {current_memory:.2f} MB")
                    gc.collect()
        
        # Process remaining chunk
        if chunk_data:
            records = extract_fields_vectorized(chunk_data, fields)
            all_data.extend(records)
        
        proc.stdout.close()
        proc.wait()
        
        if proc.returncode != 0:
            stderr_output = proc.stderr.read()
            logger.critical(f"tshark failed with exit code {proc.returncode}, stderr: {stderr_output}")
            raise subprocess.CalledProcessError(proc.returncode, cmd, output="", stderr=stderr_output)
        
        if not all_data:
            logger.critical("No data extracted from tshark output")
            return pd.DataFrame()
        
        logger.info(f"Creating DataFrame with {len(all_data)} records")
        
        # Create DataFrame with optimized dtypes
        defined_columns = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "smb2.sesid"]
        unique_fields = [f for f in fields if f not in defined_columns]
        
        df = pd.DataFrame(all_data, columns=defined_columns + unique_fields)
        
        # Optimize data types to reduce memory usage
        df = optimize_dataframe_dtypes(df)
        
        logger.info(f"Processed {len(df)} frames from tshark output, skipped {skip_count} lines")
        logger.info(f"Total lines processed: {line_count}")
        
        return df
        
    except Exception as e:
        logger.critical(f"Error in process_tshark_output_chunked: {e}")
        raise


def optimize_dataframe_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """Optimize DataFrame data types to reduce memory usage.
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with optimized dtypes
    """
    logger.debug("Optimizing DataFrame data types for memory efficiency")
    
    initial_memory = df.memory_usage(deep=True).sum() / 1024**2
    
    # Convert numeric columns to more efficient types
    for col in df.columns:
        if col in ['frame.number', 'tcp.stream']:
            df[col] = pd.to_numeric(df[col], errors='coerce', downcast='integer')
        elif col.startswith('smb2.') and col.endswith('.length'):
            df[col] = pd.to_numeric(df[col], errors='coerce', downcast='integer')
    
    # Convert string columns to category for repeated values
    string_cols = df.select_dtypes(include=['object']).columns
    for col in string_cols:
        if df[col].nunique() / len(df) < 0.5:  # If less than 50% unique values
            df[col] = df[col].astype('category')
    
    final_memory = df.memory_usage(deep=True).sum() / 1024**2
    memory_reduction = ((initial_memory - final_memory) / initial_memory) * 100
    
    logger.info(f"Memory optimization: {initial_memory:.2f}MB -> {final_memory:.2f}MB "
                f"({memory_reduction:.1f}% reduction)")
    
    return df


# Maintain backward compatibility
def process_tshark_output(cmd: List[str], fields: List[str]) -> pd.DataFrame:
    """Process tshark output - now uses optimized chunked processing."""
    return process_tshark_output_chunked(cmd, fields)


def save_to_parquet(df: pd.DataFrame, parquet_path: str):
    """Save DataFrame to Parquet file.
    
    Args:
        df: DataFrame to save
        parquet_path: Path to save the Parquet file
    """
    logger.info(f"Saving DataFrame to {parquet_path}")
    
    try:
        # Handle multi-value fields for Parquet compatibility
        multi_value_fields = ['smb2.sesid', 'smb2.cmd', 'smb2.filename', 'smb2.tid', 'smb2.nt_status', 'smb2.msg_id']
        df_copy = df.copy()
        
        for col in multi_value_fields:
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].apply(lambda x: ','.join(map(str, x)) if isinstance(x, list) else str(x) if x else '')
        
        table = pa.Table.from_pandas(df_copy, preserve_index=False)
        pq.write_table(table, parquet_path, compression='zstd')
        logger.info(f"Saved DataFrame to {parquet_path}")
        
    except Exception as e:
        logger.critical(f"Error saving Parquet file {parquet_path}: {str(e)}\n{traceback.format_exc()}")
        raise


def get_packet_count(capture_path: str) -> Optional[int]:
    """Retrieve the number of packets in a PCAP file using local capinfos.
    
    Args:
        capture_path: Path to the PCAP file
        
    Returns:
        Number of packets or None if failed
    """
    logger.info(f"Retrieving packet count for {capture_path}")
    
    try:
        cmd = ["capinfos", "-c", capture_path]
        logger.debug(f"Executing local capinfos command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
        
        for line in output.splitlines():
            if "Number of packets:" in line:
                count_str = line.split(":")[1].strip()
                try:
                    count_str_lower = count_str.lower()
                    if 'k' in count_str_lower:
                        count = int(float(count_str_lower.replace('k', '')) * 1000)
                    elif 'm' in count_str_lower:
                        count = int(float(count_str_lower.replace('m', '')) * 1000000)
                    else:
                        count = int(count_str)
                    logger.info(f"Packet count for {capture_path}: {count}")
                    return count
                except ValueError:
                    logger.critical(f"Invalid packet count format: {count_str}")
                    return None
        
        logger.critical(f"Could not parse packet count from capinfos output: {output}")
        return None
        
    except subprocess.CalledProcessError as e:
        logger.critical(f"Error running capinfos: {e.stderr}")
        return None
    except Exception as e:
        logger.critical(f"Error in get_packet_count: {str(e)}\n{traceback.format_exc()}")
        return None


def validate_pcap_file(capture_path: str) -> bool:
    """Validate PCAP file using tshark.
    
    Args:
        capture_path: Path to the PCAP file
        
    Returns:
        True if valid, False otherwise
    """
    logger.info(f"Validating PCAP: {capture_path}")
    
    if not os.path.exists(capture_path):
        logger.critical(f"PCAP file not found: {capture_path}")
        return False
    
    try:
        validate_cmd = [TSHARK_PATH, "-r", capture_path, "-c", "1"]
        logger.debug(f"Executing PCAP validation command: {' '.join(validate_cmd)}")
        result = subprocess.run(validate_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        logger.debug(f"PCAP validation stdout: {result.stdout}")
        logger.info(f"PCAP file validated")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.critical(f"Error validating PCAP: {e.stderr}")
        return False
    except Exception as e:
        logger.critical(f"Error in validate_pcap_file: {str(e)}\n{traceback.format_exc()}")
        return False


def create_session_directory(case_number: str, trace_name: str, force_reingest: bool = False) -> str:
    """Create local directory for session storage.
    
    Args:
        case_number: Case number
        trace_name: Trace name
        force_reingest: Whether to clear existing files
        
    Returns:
        Path to the session directory
    """
    from .config import get_traces_folder
    
    logger.info(f"Creating directory for case {case_number}, trace {trace_name}")
    
    try:
        traces_folder = get_traces_folder()
        base_dir = os.path.join(traces_folder, case_number)
        tracer_dir = os.path.join(base_dir, ".tracer")
        pcap_dir = os.path.join(tracer_dir, trace_name.split('.')[0])
        output_dir = os.path.join(pcap_dir, "sessions")
        
        # Create directory structure
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Created directory: {output_dir}")
        
        if force_reingest:
            clear_directory(output_dir)
            logger.info(f"Cleared {output_dir} due to force_reingest")
        
        # Verify directory exists and is writable
        if not os.path.exists(output_dir):
            raise RuntimeError(f"Directory {output_dir} does not exist after creation")
        if not os.access(output_dir, os.W_OK):
            raise RuntimeError(f"Directory {output_dir} is not writable")
        
        logger.info(f"Verified {output_dir} exists and is writable")
        return output_dir
        
    except Exception as e:
        logger.critical(f"Error in create_session_directory: {str(e)}\n{traceback.format_exc()}")
        raise


def clear_directory(directory: str):
    """Clear all files in a directory.
    
    Args:
        directory: Directory path to clear
    """
    logger.info(f"Clearing directory: {directory}")
    
    try:
        if not os.path.exists(directory):
            logger.warning(f"Directory {directory} does not exist, nothing to clear")
            return
        
        import glob
        import shutil
        
        files_to_remove = glob.glob(os.path.join(directory, "*"))
        for file_path in files_to_remove:
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    logger.debug(f"Removed file: {file_path}")
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                    logger.debug(f"Removed directory: {file_path}")
            except Exception as e:
                logger.warning(f"Could not remove {file_path}: {e}")
        
        logger.info(f"Cleared all files in {directory}")
        
    except Exception as e:
        logger.critical(f"Error in clear_directory: {str(e)}\n{traceback.format_exc()}")
        raise 