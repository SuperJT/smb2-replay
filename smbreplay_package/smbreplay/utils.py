import json
import mimetypes
import os
import re
import time
from typing import Any, Dict, List, Optional, Union

import pandas as pd


def get_share_relative_path(self, filename: str) -> str:
    """
    Given a filename (possibly a UNC path), return the path relative to the share root.
    E.g. '10.216.29.169\\share\\dir\\file.txt' -> 'dir\\file.txt'
    Handles both forward and backward slashes.
    """
    parts = re.split(r"[\\/]+", filename)
    # If the first part looks like an IP or hostname, and the second is the share, skip both
    if len(parts) > 2 and (
        re.match(r"^(\\)?[0-9a-zA-Z_.:-]+$", parts[0])
        and ("$" in parts[1] or len(parts[1]) > 0)
    ):
        return "\\".join(parts[2:])
    # If the first part is the share name, skip it
    if len(parts) > 1 and ("$" in parts[0] or len(parts[0]) > 0):
        return "\\".join(parts[1:])
    return filename


def format_bytes(size: float) -> str:
    """Format bytes to human readable format.

    Args:
        size: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable format.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60

    if minutes < 60:
        return f"{minutes}m {remaining_seconds:.1f}s"

    hours = int(minutes // 60)
    remaining_minutes = minutes % 60

    return f"{hours}h {remaining_minutes}m {remaining_seconds:.1f}s"


def safe_json_serialize(obj: Any) -> str:
    """Safely serialize object to JSON, handling non-serializable types.

    Args:
        obj: Object to serialize

    Returns:
        JSON string
    """

    def default_handler(o):
        if isinstance(o, pd.Timestamp):
            return o.isoformat()
        elif isinstance(o, pd.Series):
            return o.tolist()
        elif isinstance(o, pd.DataFrame):
            return o.to_dict("records")
        elif hasattr(o, "__dict__"):
            return str(o)
        else:
            return str(o)

    try:
        return json.dumps(obj, default=default_handler, indent=2)
    except Exception as e:
        return f'{{"error": "Failed to serialize: {str(e)}"}}'


def ensure_directory_exists(path: str) -> bool:
    """Ensure directory exists, creating if necessary.

    Args:
        path: Directory path

    Returns:
        True if directory exists or was created successfully
    """
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        return False


def get_file_info(file_path: str) -> Dict[str, Any]:
    """Get comprehensive file information.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with file information
    """
    info = {
        "path": file_path,
        "exists": False,
        "size": 0,
        "readable": False,
        "writable": False,
        "mime_type": None,
        "modified_time": None,
        "created_time": None,
    }

    try:
        if os.path.exists(file_path):
            info["exists"] = True

            stat = os.stat(file_path)
            info["size"] = stat.st_size
            info["modified_time"] = stat.st_mtime
            info["created_time"] = stat.st_ctime

            info["readable"] = os.access(file_path, os.R_OK)
            info["writable"] = os.access(file_path, os.W_OK)

            mime_type, _ = mimetypes.guess_type(file_path)
            info["mime_type"] = mime_type

    except Exception as e:
        info["error"] = str(e)

    return info


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format.

    Args:
        ip: IP address string

    Returns:
        True if valid IP address
    """
    try:
        import ipaddress

        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: Union[str, int]) -> bool:
    """Validate port number.

    Args:
        port: Port number

    Returns:
        True if valid port number
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def truncate_string(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate string to maximum length.

    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncating

    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def clean_filename(filename: str) -> str:
    """Clean filename by removing invalid characters.

    Args:
        filename: Original filename

    Returns:
        Cleaned filename
    """
    import re

    # Remove invalid characters
    cleaned = re.sub(r'[<>:"/\\|?*]', "_", filename)

    # Remove leading/trailing spaces and dots
    cleaned = cleaned.strip(" .")

    # Ensure it's not empty
    if not cleaned:
        cleaned = "unnamed"

    return cleaned


def parse_smb_timestamp(timestamp_str: str) -> Optional[float]:
    """Parse SMB timestamp string to Unix timestamp.

    Args:
        timestamp_str: SMB timestamp string

    Returns:
        Unix timestamp or None if parsing fails
    """
    try:
        # Try different timestamp formats
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = pd.to_datetime(timestamp_str, format=fmt)
                return dt.timestamp()
            except ValueError:
                continue

        # Try pandas auto-parsing as last resort
        dt = pd.to_datetime(timestamp_str)
        return dt.timestamp()

    except Exception:
        return None


def hex_dump(data: bytes, width: int = 16) -> str:
    """Generate hex dump of binary data.

    Args:
        data: Binary data
        width: Number of bytes per line

    Returns:
        Hex dump string
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")

    return "\n".join(lines)


def calculate_hash(data: Union[str, bytes], algorithm: str = "sha256") -> str:
    """Calculate hash of data.

    Args:
        data: Data to hash
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256')

    Returns:
        Hex digest of hash
    """
    import hashlib

    if isinstance(data, str):
        data = data.encode("utf-8")

    if algorithm.lower() == "md5":
        return hashlib.md5(data).hexdigest()
    elif algorithm.lower() == "sha1":
        return hashlib.sha1(data).hexdigest()
    elif algorithm.lower() == "sha256":
        return hashlib.sha256(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def merge_dictionaries(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple dictionaries, with later ones taking precedence.

    Args:
        *dicts: Dictionaries to merge

    Returns:
        Merged dictionary
    """
    result = {}
    for d in dicts:
        if d:
            result.update(d)
    return result


def flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "."
) -> Dict[str, Any]:
    """Flatten nested dictionary.

    Args:
        d: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator for nested keys

    Returns:
        Flattened dictionary
    """
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def batch_process(items: List[Any], batch_size: int = 1000):
    """Process items in batches.

    Args:
        items: List of items to process
        batch_size: Size of each batch

    Yields:
        Batches of items
    """
    for i in range(0, len(items), batch_size):
        yield items[i : i + batch_size]


def retry_operation(
    func, max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0
):
    """Retry operation with exponential backoff.

    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        delay: Initial delay between retries
        backoff: Backoff multiplier

    Returns:
        Result of function call

    Raises:
        Last exception if all retries fail
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                time.sleep(delay * (backoff**attempt))
            else:
                raise last_exception


def convert_size_string(size_str: str) -> int:
    """Convert size string to bytes.

    Args:
        size_str: Size string (e.g., "1.5MB", "500KB")

    Returns:
        Size in bytes
    """
    import re

    # Extract number and unit
    match = re.match(r"(\d+(?:\.\d+)?)\s*([A-Za-z]*)", size_str.strip())
    if not match:
        raise ValueError(f"Invalid size format: {size_str}")

    number = float(match.group(1))
    unit = match.group(2).upper()

    # Convert to bytes
    multipliers = {
        "": 1,
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
    }

    if unit not in multipliers:
        raise ValueError(f"Unknown size unit: {unit}")

    return int(number * multipliers[unit])


def get_terminal_size() -> tuple:
    """Get terminal size.

    Returns:
        Tuple of (width, height)
    """
    try:
        import shutil

        size = shutil.get_terminal_size()
        return size.columns, size.lines
    except Exception:
        return 80, 24  # Default size


def create_progress_bar(current: int, total: int, width: int = 40) -> str:
    """Create a simple progress bar.

    Args:
        current: Current progress
        total: Total items
        width: Width of progress bar

    Returns:
        Progress bar string
    """
    if total == 0:
        return "[" + "=" * width + "] 100%"

    percentage = min(100, (current / total) * 100)
    filled = int((current / total) * width)
    bar = "=" * filled + "-" * (width - filled)

    return f"[{bar}] {percentage:.1f}%"


class Timer:
    """Simple timer context manager."""

    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()

    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        if self.start_time is None:
            return 0.0
        end_time = self.end_time or time.time()
        return end_time - self.start_time

    def __str__(self) -> str:
        return f"{self.name}: {format_duration(self.elapsed)}"
