"""
TShark PCAP Processing Module.
Handles PCAP file processing using tshark for SMB2 protocol analysis.
"""

import os
import subprocess
import shlex
import traceback
import json
import psutil
from typing import List, Dict, Tuple, Any, Optional
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from .config import get_logger
from .constants import TSHARK_PATH, get_all_fields

logger = get_logger()


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


def extract_fields(line: str, fields: list[str]) -> tuple[int, int, str, str, str, dict[str, str | set[str]]]:
    """Parse a tshark output line into a field dictionary.
    
    Args:
        line: Raw tshark output line
        fields: List of field names
        
    Returns:
        Tuple of (frame, stream, ip_src, ip_dst, sesid, field_dict)
    """
    logger.debug(f"Extracting fields from line: {line.strip()[:100]}...")
    
    try:
        split_line = line.split("|")
        if not split_line or not split_line[0].strip() or len(split_line) < 5:
            logger.warning(f"Invalid line format (split on |): {line.strip()[:100]}...")
            return 0, -1, "", "", "", {}
        
        if len(split_line) < len(fields):
            logger.warning(f"Line has {len(split_line)} fields, expected at least {len(fields)}: {line.strip()[:100]}...")
            split_line.extend([""] * (len(fields) - len(split_line)))
        
        field_dict: dict[str, str | set[str]] = {}
        for i, value in enumerate(split_line[:len(fields)]):
            cleaned_value = value.split("\x02")[0] if value else ""
            field_dict[fields[i]] = cleaned_value
        
        frame_number = field_dict.get("frame.number", "")
        # Ensure frame_number is a str for isdigit/int
        if isinstance(frame_number, set):
            frame_number_str = next(iter(frame_number), "")
        else:
            frame_number_str = frame_number
        if frame_number_str.isdigit() and int(frame_number_str) <= 10:
            logger.debug(f"Extracted fields (first 5): {dict(list(field_dict.items())[:5])}")
        
        frame = 0
        stream_str = field_dict.get("tcp.stream", "")
        if isinstance(stream_str, set):
            stream_str_val = next(iter(stream_str), "")
        else:
            stream_str_val = stream_str
        stream = int(stream_str_val) if stream_str_val and stream_str_val.isdigit() else -1
        if not stream_str_val or not stream_str_val.isdigit():
            logger.warning(f"Invalid tcp.stream '{stream_str_val}' in line: {line.strip()[:100]}...")
        
        ip_src = field_dict.pop("ip.src", field_dict.pop("ipv6.src", ""))
        ip_dst = field_dict.pop("ip.dst", field_dict.pop("ipv6.dst", ""))
        sesid: set[str] | str = field_dict.pop("smb2.sesid", set())
        # If sesid is a set, join as comma-separated string for sesid_value
        if isinstance(sesid, set):
            sesid_value = ','.join(sorted(sesid))
        else:
            sesid_value = str(sesid)
        field_dict.pop("frame.number", None)
        field_dict.pop("tcp.stream", None)
        
        # Ensure key fields exist
        key_fields = ['smb2.cmd', 'smb2.filename', 'smb2.tid']
        for field in key_fields:
            if field not in field_dict:
                field_dict[field] = ""
        
        # Handle multi-value fields
        multi_value_fields = ['smb2.sesid', 'smb2.cmd', 'smb2.filename', 'smb2.tid', 'smb2.nt_status', 'smb2.msg_id']
        for field in multi_value_fields:
            if field in field_dict and field_dict[field]:
                val = field_dict[field]
                if isinstance(val, str):
                    if ',' in val:
                        field_dict[field] = {v.strip() for v in val.split(',') if v.strip()}
                    else:
                        field_dict[field] = {val} if val else set()
                else:
                    str_val = str(val)
                    if ',' in str_val:
                        field_dict[field] = {v.strip() for v in str_val.split(',') if v.strip()}
                    else:
                        field_dict[field] = {str_val} if str_val else set()
        
        return int(frame), int(stream), str(ip_src), str(ip_dst), str(sesid_value), field_dict
        
    except Exception as e:
        logger.critical(f"Error in extract_fields: {str(e)}\n{traceback.format_exc()}")
        return 0, -1, "", "", "", {}


def process_tshark_output(cmd: List[str], fields: List[str]) -> pd.DataFrame:
    """Process tshark output into a DataFrame.
    
    Args:
        cmd: Tshark command arguments
        fields: List of field names
        
    Returns:
        DataFrame with extracted SMB2 data
    """
    logger.info(f"Processing tshark output with command: {' '.join(cmd)[:200]}...")
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        data = []
        line_count = 0
        skip_count = 0
        header_skipped = False
        header_fields = None
        
        if proc.stdout is None:
            logger.critical("proc.stdout is None; cannot read tshark output")
            return pd.DataFrame()
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
            
            line_count += 1
            if line_count % 1000 == 0:
                logger.info(f"Processed {line_count} lines, memory usage: {psutil.Process().memory_info().rss / 1024**2:.2f} MB")
            
            if line_count <= 10:
                logger.debug(f"Raw line {line_count}: {line[:200]}...")
            
            try:
                frame, stream, ip_src, ip_dst, sesid, field_dict = extract_fields(line, fields)
                corrected_frame = line_count
                field_dict['frame.number'] = str(corrected_frame)
                
                # When constructing the record, if sesid is a set, join as comma-separated string for DataFrame
                record = {
                    "frame.number": corrected_frame,
                    "tcp.stream": stream,
                    "ip.src": ip_src,
                    "ip.dst": ip_dst,
                    "smb2.sesid": ','.join(sesid) if isinstance(sesid, set) else sesid,
                    **{k: (','.join(v) if isinstance(v, set) else v) for k, v in field_dict.items()}
                }
                data.append(record)
                
            except (KeyError, ValueError) as e:
                skip_count += 1
                if skip_count <= 5:
                    logger.warning(f"Skipping line {line_count} due to error: {e} - Raw: {line[:100]}...")
                continue
        
        if proc.stdout is not None:
            proc.stdout.close()
        proc.wait()
        
        if proc.returncode != 0:
            stderr_output = proc.stderr.read() if proc.stderr is not None else ""
            logger.critical(f"tshark failed with exit code {proc.returncode}, stderr: {stderr_output}")
            raise subprocess.CalledProcessError(proc.returncode, cmd, output=json.dumps(data, indent=2) if data else "", stderr=stderr_output)
        
        if not data:
            logger.critical("No data extracted from tshark output")
            return pd.DataFrame()
        
        logger.info(f"Creating DataFrame with {len(data)} records, memory usage: {psutil.Process().memory_info().rss / 1024**2:.2f} MB")
        
        defined_columns = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "smb2.sesid"]
        unique_fields = [f for f in fields if f not in defined_columns]
        df = pd.DataFrame(data, columns=defined_columns + unique_fields)
        
        logger.info(f"Processed {len(df)} frames from tshark output, skipped {skip_count} lines")
        logger.info(f"Total lines processed: {line_count}")
        
        # Log DataFrame memory usage before optimization
        df_memory_mb = df.memory_usage(deep=True).sum() / 1024**2
        logger.info(f"DataFrame memory usage before optimization: {df_memory_mb:.2f} MB")
        
        # Optimize DataFrame
        df = _optimize_dataframe(df)
        
        # Log DataFrame memory usage after optimization
        df_memory_mb_opt = df.memory_usage(deep=True).sum() / 1024**2
        logger.info(f"DataFrame memory usage after optimization: {df_memory_mb_opt:.2f} MB")
        
        return df
        
    except Exception as e:
        logger.critical(f"Error in process_tshark_output: {str(e)}\n{traceback.format_exc()}")
        raise


def _optimize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Optimize DataFrame memory usage and data types."""
    # Normalize smb2.sesid early
    if 'smb2.sesid' in df.columns:
        multi_value_count = df['smb2.sesid'].str.contains(',').sum()
        logger.debug(f"Found {multi_value_count} rows with multi-valued smb2.sesid")
        df['smb2.sesid'] = df['smb2.sesid'].apply(lambda x: ','.join(x) if isinstance(x, list) else x if x else '')
        logger.debug(f"Normalized smb2.sesid values (first 10): {list(df['smb2.sesid'].head(10))}")
    
    # Optimize numeric columns
    if 'tcp.stream' in df.columns:
        df['tcp.stream'] = pd.to_numeric(df['tcp.stream'], errors='coerce', downcast='integer')
        logger.info(f"Converted tcp.stream to dtype: {df['tcp.stream'].dtype}")
    
    # Downcast numeric columns
    for col in df.columns:
        if df[col].dtype == 'float64':
            df[col] = pd.to_numeric(df[col], errors='coerce', downcast='float')
        elif df[col].dtype == 'int64':
            df[col] = pd.to_numeric(df[col], errors='coerce', downcast='integer')
    
    # Handle hex fields
    hex_fields = ['smb2.nt_status', 'smb2.tid', 'smb2.sesid', 'smb2.fid', 'smb2.flags']
    for col in hex_fields:
        if col in df.columns:
            df[col] = df[col].map(lambda x: x[0] if isinstance(x, list) and x else x if not isinstance(x, list) else '')
            if col == 'smb2.tid':
                logger.debug(f"Normalized smb2.tid values (first 10): {list(df['smb2.tid'].head(10))}")
    
    # Optimize string columns
    if 'frame.number' in df.columns:
        df['frame.number'] = pd.to_numeric(df['frame.number'], errors='coerce', downcast='integer')
    if 'ip.src' in df.columns:
        df['ip.src'] = df['ip.src'].astype('string')
    if 'ip.dst' in df.columns:
        df['ip.dst'] = df['ip.dst'].astype('string')
    if 'smb2.msg_id' in df.columns:
        df['smb2.msg_id'] = df['smb2.msg_id'].map(lambda x: x[0] if isinstance(x, list) and x else x)
        # Use Int64 instead of UInt64 to handle NaN values properly
        df['smb2.msg_id'] = pd.to_numeric(df['smb2.msg_id'], errors='coerce').astype('Int64')
    
    return df


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