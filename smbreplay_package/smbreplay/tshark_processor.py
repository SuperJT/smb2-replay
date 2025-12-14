"""
TShark PCAP Processing Module.
Handles PCAP file processing using tshark for SMB2 protocol analysis.
"""

import contextlib
import json
import os
import select
import subprocess
import time
import traceback

import pandas as pd
import psutil
import pyarrow as pa
import pyarrow.parquet as pq

from .config import get_logger
from .constants import TSHARK_PATH

logger = get_logger()


def _sanitize_path_component(component: str) -> str:
    """Sanitize a path component to prevent path traversal attacks.

    Removes or replaces dangerous characters and sequences that could
    allow escaping the intended directory structure.

    Args:
        component: A single path component (e.g., case_number, trace_name)

    Returns:
        Sanitized path component safe for use in file paths

    Raises:
        ValueError: If component is empty or contains only dangerous characters
    """
    if not component:
        raise ValueError("Path component cannot be empty")

    # Remove path separators and traversal sequences
    sanitized = component.replace("/", "_").replace("\\", "_")
    sanitized = sanitized.replace("..", "_")

    # Remove null bytes (can truncate paths in some systems)
    sanitized = sanitized.replace("\x00", "")

    # Strip leading/trailing whitespace and dots (could be used for traversal)
    sanitized = sanitized.strip(". \t\n\r")

    if not sanitized:
        raise ValueError(
            f"Path component '{component}' contains only invalid characters"
        )

    return sanitized


def _validate_path_within_base(path: str, base_dir: str) -> bool:
    """Validate that a path is within the expected base directory.

    Uses realpath to resolve symlinks and ensure the final path
    doesn't escape the allowed directory structure.

    Args:
        path: The path to validate
        base_dir: The base directory that path must be within

    Returns:
        True if path is safely within base_dir

    Raises:
        ValueError: If path would escape base_dir
    """
    # Resolve to absolute paths, following symlinks
    real_path = os.path.realpath(path)
    real_base = os.path.realpath(base_dir)

    # Check if the resolved path starts with the base directory
    if not real_path.startswith(real_base + os.sep) and real_path != real_base:
        raise ValueError(
            f"Path traversal detected: '{path}' resolves outside base directory '{base_dir}'"
        )

    return True


class InvalidPcapError(ValueError):
    """Raised when a PCAP file is invalid or doesn't exist."""

    pass


# Valid PCAP file extensions
VALID_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".dmp"}


def _validate_pcap_file(capture: str) -> None:
    """Validate that the capture file exists and has a valid extension.

    Args:
        capture: Path to the PCAP file

    Raises:
        InvalidPcapError: If the file doesn't exist or has invalid extension
    """
    if not capture:
        raise InvalidPcapError("Capture path cannot be empty")

    if not os.path.exists(capture):
        raise InvalidPcapError(f"PCAP file not found: {capture}")

    if not os.path.isfile(capture):
        raise InvalidPcapError(f"Path is not a file: {capture}")

    # Check file extension
    _, ext = os.path.splitext(capture.lower())
    if ext not in VALID_PCAP_EXTENSIONS:
        raise InvalidPcapError(
            f"Invalid file extension '{ext}'. Expected one of: {', '.join(VALID_PCAP_EXTENSIONS)}"
        )

    # Check file is readable
    if not os.access(capture, os.R_OK):
        raise InvalidPcapError(f"PCAP file is not readable: {capture}")

    # Basic file size check (PCAP files have headers, so > 24 bytes minimum)
    try:
        file_size = os.path.getsize(capture)
        if file_size < 24:
            raise InvalidPcapError(
                f"PCAP file too small ({file_size} bytes), may be corrupted: {capture}"
            )
    except OSError as e:
        raise InvalidPcapError(f"Cannot read PCAP file size: {e}") from e


def build_tshark_command(
    capture: str,
    fields: list[str],
    reassembly: bool = False,
    packet_limit: int | None = None,
    log_level: str = "debug",
    temp_dir: str = "/tmp",
    verbose: bool = False,
) -> tuple[list[str], list[str]]:
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

    Raises:
        InvalidPcapError: If the capture file is invalid
    """
    # Validate PCAP file before building command
    _validate_pcap_file(capture)

    logger.info(f"Building local tshark command for capture: {capture}")

    tshark_args = [
        TSHARK_PATH,
        "-r",
        capture,
        "-Y",
        "smb2",
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "header=y",
        "-E",
        "occurrence=a",
        "-q",
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


def extract_fields(
    line: str, fields: list[str]
) -> tuple[int, int, str, str, str, dict[str, str | set[str]]]:
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
            logger.warning(
                f"Line has {len(split_line)} fields, expected at least {len(fields)}: {line.strip()[:100]}..."
            )
            split_line.extend([""] * (len(fields) - len(split_line)))

        field_dict: dict[str, str | set[str]] = {}
        for i, value in enumerate(split_line[: len(fields)]):
            cleaned_value = value.split("\x02")[0] if value else ""
            field_dict[fields[i]] = cleaned_value

        frame_number = field_dict.get("frame.number", "")
        # Ensure frame_number is a str for isdigit/int
        if isinstance(frame_number, set):
            frame_number_str = next(iter(frame_number), "")
        else:
            frame_number_str = frame_number
        if frame_number_str.isdigit() and int(frame_number_str) <= 10:
            logger.debug(
                f"Extracted fields (first 5): {dict(list(field_dict.items())[:5])}"
            )

        frame = 0
        stream_str = field_dict.get("tcp.stream", "")
        if isinstance(stream_str, set):
            stream_str_val = next(iter(stream_str), "")
        else:
            stream_str_val = stream_str
        stream = (
            int(stream_str_val) if stream_str_val and stream_str_val.isdigit() else -1
        )
        if not stream_str_val or not stream_str_val.isdigit():
            logger.warning(
                f"Invalid tcp.stream '{stream_str_val}' in line: {line.strip()[:100]}..."
            )

        ip_src = field_dict.pop("ip.src", field_dict.pop("ipv6.src", ""))
        ip_dst = field_dict.pop("ip.dst", field_dict.pop("ipv6.dst", ""))
        sesid: set[str] | str = field_dict.pop("smb2.sesid", set())
        # If sesid is a set, join as comma-separated string for sesid_value
        if isinstance(sesid, set):
            sesid_value = ",".join(sorted(sesid))
        else:
            sesid_value = str(sesid)
        field_dict.pop("frame.number", None)
        field_dict.pop("tcp.stream", None)

        # Ensure key fields exist
        key_fields = ["smb2.cmd", "smb2.filename", "smb2.tid"]
        for field in key_fields:
            if field not in field_dict:
                field_dict[field] = ""

        # Handle multi-value fields
        multi_value_fields = [
            "smb2.sesid",
            "smb2.cmd",
            "smb2.filename",
            "smb2.tid",
            "smb2.nt_status",
            "smb2.msg_id",
        ]
        for field in multi_value_fields:
            if field_dict.get(field):
                val = field_dict[field]
                if isinstance(val, str):
                    if "," in val:
                        field_dict[field] = {
                            v.strip() for v in val.split(",") if v.strip()
                        }
                    else:
                        field_dict[field] = {val} if val else set()
                else:
                    str_val = str(val)
                    if "," in str_val:
                        field_dict[field] = {
                            v.strip() for v in str_val.split(",") if v.strip()
                        }
                    else:
                        field_dict[field] = {str_val} if str_val else set()

        return (
            int(frame),
            int(stream),
            str(ip_src),
            str(ip_dst),
            str(sesid_value),
            field_dict,
        )

    except Exception as e:
        logger.critical(f"Error in extract_fields: {e!s}\n{traceback.format_exc()}")
        return 0, -1, "", "", "", {}


def process_tshark_output(
    cmd: list[str],
    fields: list[str],
    max_records: int = 10_000_000,
    timeout_seconds: int = 3600,
    idle_timeout_seconds: int = 300,
) -> pd.DataFrame:
    """Process tshark output into a DataFrame.

    Args:
        cmd: Tshark command arguments
        fields: List of field names
        max_records: Maximum records to process (default 10M, ~4GB memory)
        timeout_seconds: Maximum total processing time (default 1 hour)
        idle_timeout_seconds: Maximum time waiting for data (default 5 minutes)

    Returns:
        DataFrame with extracted SMB2 data

    Raises:
        TimeoutError: If processing exceeds timeout limits
    """
    logger.info(f"Processing tshark output with command: {' '.join(cmd)[:200]}...")
    start_time = time.time()

    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        data = []
        line_count = 0
        skip_count = 0
        header_skipped = False
        header_fields = None

        if proc.stdout is None:
            logger.critical("proc.stdout is None; cannot read tshark output")
            return pd.DataFrame()

        # Use select for timeout handling on stdout reads
        stdout_fd = proc.stdout.fileno()

        while True:
            # Check total timeout
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                raise TimeoutError(
                    f"Processing exceeded total timeout of {timeout_seconds}s "
                    f"(processed {line_count} lines)"
                )

            # Use select with idle timeout to avoid indefinite blocking
            readable, _, _ = select.select([stdout_fd], [], [], idle_timeout_seconds)
            if not readable:
                # Check if process is still running
                if proc.poll() is not None:
                    break  # Process finished
                raise TimeoutError(
                    f"No data received for {idle_timeout_seconds}s "
                    f"(idle timeout, processed {line_count} lines)"
                )

            line = proc.stdout.readline()
            if not line:
                break  # EOF

            line = line.strip()
            if not line:
                continue

            if not header_skipped:
                header_fields = line.split("|")
                if header_fields != fields[: len(header_fields)]:
                    logger.warning(
                        f"Header fields mismatch! Expected: {fields[:10]}, Got: {header_fields[:10]}"
                    )
                logger.debug(f"Header row: {line[:200]}...")
                header_skipped = True
                continue

            line_count += 1
            if line_count % 1000 == 0:
                logger.info(
                    f"Processed {line_count} lines, memory usage: {psutil.Process().memory_info().rss / 1024**2:.2f} MB"
                )

            if line_count <= 10:
                logger.debug(f"Raw line {line_count}: {line[:200]}...")

            try:
                frame, stream, ip_src, ip_dst, sesid, field_dict = extract_fields(
                    line, fields
                )
                corrected_frame = line_count
                field_dict["frame.number"] = str(corrected_frame)

                # When constructing the record, if sesid is a set, join as comma-separated string for DataFrame
                record = {
                    "frame.number": corrected_frame,
                    "tcp.stream": stream,
                    "ip.src": ip_src,
                    "ip.dst": ip_dst,
                    "smb2.sesid": ",".join(sesid) if isinstance(sesid, set) else sesid,
                    **{
                        k: (",".join(v) if isinstance(v, set) else v)
                        for k, v in field_dict.items()
                    },
                }
                data.append(record)

                # Check memory limit to prevent unbounded growth
                if len(data) >= max_records:
                    logger.warning(
                        f"Reached max_records limit ({max_records}). "
                        f"Truncating output to prevent memory exhaustion."
                    )
                    break

            except (KeyError, ValueError) as e:
                skip_count += 1
                if skip_count <= 5:
                    logger.warning(
                        f"Skipping line {line_count} due to error: {e} - Raw: {line[:100]}..."
                    )
                continue

        # Clean up process resources
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        proc.wait()

        if proc.returncode != 0:
            logger.critical(f"tshark failed with exit code {proc.returncode}")
            raise subprocess.CalledProcessError(
                proc.returncode,
                cmd,
                output=json.dumps(data, indent=2) if data else "",
            )

        if not data:
            logger.critical("No data extracted from tshark output")
            return pd.DataFrame()

        logger.info(
            f"Creating DataFrame with {len(data)} records, memory usage: {psutil.Process().memory_info().rss / 1024**2:.2f} MB"
        )

        defined_columns = [
            "frame.number",
            "tcp.stream",
            "ip.src",
            "ip.dst",
            "smb2.sesid",
        ]
        unique_fields = [f for f in fields if f not in defined_columns]
        df = pd.DataFrame(data, columns=defined_columns + unique_fields)

        logger.info(
            f"Processed {len(df)} frames from tshark output, skipped {skip_count} lines"
        )
        logger.info(f"Total lines processed: {line_count}")

        # Log DataFrame memory usage before optimization
        df_memory_mb = df.memory_usage(deep=True).sum() / 1024**2
        logger.info(
            f"DataFrame memory usage before optimization: {df_memory_mb:.2f} MB"
        )

        # Optimize DataFrame
        df = _optimize_dataframe(df)

        # Log DataFrame memory usage after optimization
        df_memory_mb_opt = df.memory_usage(deep=True).sum() / 1024**2
        logger.info(
            f"DataFrame memory usage after optimization: {df_memory_mb_opt:.2f} MB"
        )

        return df

    except Exception as e:
        logger.critical(
            f"Error in process_tshark_output: {e!s}\n{traceback.format_exc()}"
        )
        raise
    finally:
        # Ensure process cleanup even if exception occurs
        if proc is not None:
            if proc.stdout is not None:
                with contextlib.suppress(Exception):
                    proc.stdout.close()
            if proc.stderr is not None:
                with contextlib.suppress(Exception):
                    proc.stderr.close()
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()  # Force kill if terminate doesn't work


def _optimize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Optimize DataFrame memory usage and data types."""
    # Normalize smb2.sesid early
    if "smb2.sesid" in df.columns:
        multi_value_count = df["smb2.sesid"].str.contains(",").sum()
        logger.debug(f"Found {multi_value_count} rows with multi-valued smb2.sesid")
        df["smb2.sesid"] = df["smb2.sesid"].apply(
            lambda x: ",".join(x) if isinstance(x, list) else x if x else ""
        )
        logger.debug(
            f"Normalized smb2.sesid values (first 10): {list(df['smb2.sesid'].head(10))}"
        )

    # Optimize numeric columns
    if "tcp.stream" in df.columns:
        df["tcp.stream"] = pd.to_numeric(
            df["tcp.stream"], errors="coerce", downcast="integer"
        )
        logger.info(f"Converted tcp.stream to dtype: {df['tcp.stream'].dtype}")

    # Downcast numeric columns
    for col in df.columns:
        if df[col].dtype == "float64":
            df[col] = pd.to_numeric(df[col], errors="coerce", downcast="float")
        elif df[col].dtype == "int64":
            df[col] = pd.to_numeric(df[col], errors="coerce", downcast="integer")

    # Handle hex fields
    hex_fields = ["smb2.nt_status", "smb2.tid", "smb2.sesid", "smb2.fid", "smb2.flags"]
    for col in hex_fields:
        if col in df.columns:
            df[col] = df[col].map(
                lambda x: (
                    x[0]
                    if isinstance(x, list) and x
                    else x
                    if not isinstance(x, list)
                    else ""
                )
            )
            if col == "smb2.tid":
                logger.debug(
                    f"Normalized smb2.tid values (first 10): {list(df['smb2.tid'].head(10))}"
                )

    # Optimize string columns
    if "frame.number" in df.columns:
        df["frame.number"] = pd.to_numeric(
            df["frame.number"], errors="coerce", downcast="integer"
        )
    if "ip.src" in df.columns:
        df["ip.src"] = df["ip.src"].astype("string")
    if "ip.dst" in df.columns:
        df["ip.dst"] = df["ip.dst"].astype("string")
    if "smb2.msg_id" in df.columns:
        df["smb2.msg_id"] = df["smb2.msg_id"].map(
            lambda x: x[0] if isinstance(x, list) and x else x
        )
        # Keep as string for now to avoid casting issues
        df["smb2.msg_id"] = df["smb2.msg_id"].astype("string")

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
        multi_value_fields = [
            "smb2.sesid",
            "smb2.cmd",
            "smb2.filename",
            "smb2.tid",
            "smb2.nt_status",
            "smb2.msg_id",
        ]
        df_copy = df.copy()

        for col in multi_value_fields:
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].apply(
                    lambda x: (
                        ",".join(map(str, x))
                        if isinstance(x, list)
                        else str(x)
                        if x
                        else ""
                    )
                )

        table = pa.Table.from_pandas(df_copy, preserve_index=False)
        pq.write_table(table, parquet_path, compression="zstd")
        logger.info(f"Saved DataFrame to {parquet_path}")

    except Exception as e:
        logger.critical(
            f"Error saving Parquet file {parquet_path}: {e!s}\n{traceback.format_exc()}"
        )
        raise


def get_packet_count(capture_path: str) -> int | None:
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
                    if "k" in count_str_lower:
                        count = int(float(count_str_lower.replace("k", "")) * 1000)
                    elif "m" in count_str_lower:
                        count = int(float(count_str_lower.replace("m", "")) * 1000000)
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
        logger.critical(f"Error in get_packet_count: {e!s}\n{traceback.format_exc()}")
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
        result = subprocess.run(
            validate_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logger.debug(f"PCAP validation stdout: {result.stdout}")
        logger.info("PCAP file validated")
        return True

    except subprocess.CalledProcessError as e:
        logger.critical(f"Error validating PCAP: {e.stderr}")
        return False
    except Exception as e:
        logger.critical(f"Error in validate_pcap_file: {e!s}\n{traceback.format_exc()}")
        return False


def create_session_directory(
    case_number: str, trace_name: str, force_reingest: bool = False
) -> str:
    """Create local directory for session storage.

    Args:
        case_number: Case number
        trace_name: Trace name
        force_reingest: Whether to clear existing files

    Returns:
        Path to the session directory

    Raises:
        ValueError: If case_number or trace_name contain path traversal sequences
    """
    from .config import get_session_output_dir

    logger.info(f"Creating directory for case {case_number}, trace {trace_name}")

    try:
        # Sanitize inputs to prevent path traversal attacks
        safe_case_number = _sanitize_path_component(case_number)
        safe_trace_name = _sanitize_path_component(trace_name.split(".")[0])

        # Use session_output_dir for writing processed data (writable location)
        session_output = get_session_output_dir()
        base_dir = os.path.join(session_output, safe_case_number)
        tracer_dir = os.path.join(base_dir, ".tracer")
        pcap_dir = os.path.join(tracer_dir, safe_trace_name)
        output_dir = os.path.join(pcap_dir, "sessions")

        # Validate the constructed path is within session_output (defense in depth)
        _validate_path_within_base(output_dir, session_output)

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
        logger.critical(
            f"Error in create_session_directory: {e!s}\n{traceback.format_exc()}"
        )
        raise


def clear_directory(directory: str, base_dir: str = None):
    """Clear all files in a directory.

    Args:
        directory: Directory path to clear
        base_dir: Optional base directory to validate against. If provided,
                  directory must be within base_dir (prevents path traversal).

    Raises:
        ValueError: If directory is outside base_dir when base_dir is provided
        ValueError: If directory is a symlink (security risk)
    """
    logger.info(f"Clearing directory: {directory}")

    try:
        if not os.path.exists(directory):
            logger.warning(f"Directory {directory} does not exist, nothing to clear")
            return

        # Security: Reject symlinks to prevent following to unintended locations
        if os.path.islink(directory):
            raise ValueError(f"Refusing to clear symlink directory: {directory}")

        # Security: Validate directory is within expected base (if provided)
        if base_dir:
            _validate_path_within_base(directory, base_dir)
        else:
            # If no base_dir provided, at minimum validate it's within session output
            from .config import get_session_output_dir

            session_output = get_session_output_dir()
            _validate_path_within_base(directory, session_output)

        import glob
        import shutil

        files_to_remove = glob.glob(os.path.join(directory, "*"))
        for file_path in files_to_remove:
            try:
                # Skip symlinks for safety
                if os.path.islink(file_path):
                    logger.warning(f"Skipping symlink: {file_path}")
                    continue

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
        logger.critical(f"Error in clear_directory: {e!s}\n{traceback.format_exc()}")
        raise
