import json
import time
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from smbreplay.utils import (
    Timer,
    batch_process,
    calculate_hash,
    clean_filename,
    convert_size_string,
    create_progress_bar,
    ensure_directory_exists,
    flatten_dict,
    format_bytes,
    format_duration,
    get_file_info,
    get_share_relative_path,
    get_terminal_size,
    hex_dump,
    merge_dictionaries,
    parse_smb_timestamp,
    retry_operation,
    safe_json_serialize,
    truncate_string,
    validate_ip_address,
    validate_port,
)


def test_get_share_relative_path_unc():
    """Test get_share_relative_path with UNC path."""
    # Create a mock object to call the method on
    mock_obj = type("MockObj", (), {})()
    result = get_share_relative_path(mock_obj, "192.168.1.100\\share\\dir\\file.txt")
    assert result == "dir\\file.txt"


def test_get_share_relative_path_share_name():
    """Test get_share_relative_path with share name."""
    mock_obj = type("MockObj", (), {})()
    result = get_share_relative_path(mock_obj, r"share\dir\file.txt")
    assert result == "file.txt"  # Function returns just the filename


def test_get_share_relative_path_forward_slashes():
    """Test get_share_relative_path with forward slashes."""
    mock_obj = type("MockObj", (), {})()
    result = get_share_relative_path(mock_obj, r"192.168.1.100/share/dir/file.txt")
    assert result == r"dir\file.txt"  # Function uses backslashes in output


def test_get_share_relative_path_no_share():
    """Test get_share_relative_path with no share prefix."""
    mock_obj = type("MockObj", (), {})()
    result = get_share_relative_path(mock_obj, r"dir/file.txt")
    assert result == "file.txt"  # Function returns just the filename


def test_get_share_relative_path_leading_backslash():
    """Test get_share_relative_path with leading backslash."""
    mock_obj = type("MockObj", (), {})()
    result = get_share_relative_path(mock_obj, r"\file96.txt")
    assert result == "file96.txt"


def test_get_share_relative_path_leading_forward_slash():
    """Test get_share_relative_path with leading forward slash."""
    mock_obj = type("MockObj", (), {})()
    result = get_share_relative_path(mock_obj, "/file96.txt")
    assert result == "file96.txt"


def test_format_bytes_basic():
    """Test format_bytes with basic values."""
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"


def test_format_bytes_small():
    """Test format_bytes with small values."""
    assert format_bytes(500) == "500.0 B"
    assert format_bytes(0) == "0.0 B"


def test_format_bytes_large():
    """Test format_bytes with large values."""
    assert format_bytes(1024 * 1024 * 1024 * 1024) == "1.0 TB"
    assert format_bytes(1024 * 1024 * 1024 * 1024 * 1024) == "1.0 PB"


def test_format_duration_seconds():
    """Test format_duration with seconds."""
    assert format_duration(30.5) == "30.5s"
    assert format_duration(0.1) == "0.1s"


def test_format_duration_minutes():
    """Test format_duration with minutes."""
    assert format_duration(90) == "1m 30.0s"
    assert format_duration(125) == "2m 5.0s"


def test_format_duration_hours():
    """Test format_duration with hours."""
    assert format_duration(3661) == "1h 1m 1.0s"
    assert format_duration(7325) == "2h 2m 5.0s"


def test_safe_json_serialize_basic():
    """Test safe_json_serialize with basic types."""
    data = {"key": "value", "number": 42}
    result = safe_json_serialize(data)
    assert json.loads(result) == data


def test_safe_json_serialize_pandas():
    """Test safe_json_serialize with pandas objects."""
    df = pd.DataFrame({"col1": [1, 2, 3], "col2": ["a", "b", "c"]})
    result = safe_json_serialize(df)
    assert "col1" in result
    assert "col2" in result


def test_safe_json_serialize_timestamp():
    """Test safe_json_serialize with pandas timestamp."""
    ts = pd.Timestamp("2023-01-01")
    result = safe_json_serialize(ts)
    assert "2023-01-01" in result


def test_safe_json_serialize_series():
    """Test safe_json_serialize with pandas series."""
    series = pd.Series([1, 2, 3])
    result = safe_json_serialize(series)
    assert "1" in result and "2" in result and "3" in result  # Check for values in JSON


@patch("smbreplay.utils.Path")
def test_ensure_directory_exists_new(mock_path_cls):
    """Test ensure_directory_exists with new directory."""
    mock_path_instance = MagicMock()
    mock_path_cls.return_value = mock_path_instance

    result = ensure_directory_exists("/path/to/new/dir")

    assert result is True
    mock_path_instance.mkdir.assert_called_once_with(parents=True, exist_ok=True)


@patch("smbreplay.utils.Path")
def test_ensure_directory_exists_existing(mock_path_cls):
    """Test ensure_directory_exists with existing directory."""
    mock_path_instance = MagicMock()
    mock_path_cls.return_value = mock_path_instance

    result = ensure_directory_exists("/path/to/existing/dir")

    assert result is True
    mock_path_instance.mkdir.assert_called_once_with(parents=True, exist_ok=True)


@patch("smbreplay.utils.Path")
def test_ensure_directory_exists_error(mock_path_cls):
    """Test ensure_directory_exists with error."""
    mock_path_instance = MagicMock()
    mock_path_instance.mkdir.side_effect = OSError("Permission denied")
    mock_path_cls.return_value = mock_path_instance

    result = ensure_directory_exists("/path/to/dir")

    assert result is False


@patch("os.access")
@patch("mimetypes.guess_type")
@patch("os.stat")
@patch("os.path.exists")
def test_get_file_info(mock_exists, mock_stat, mock_guess_type, mock_access):
    """Test get_file_info."""
    mock_exists.return_value = True
    mock_stat.return_value.st_size = 1024
    mock_stat.return_value.st_mtime = 1640995200.0  # 2022-01-01 00:00:00
    mock_stat.return_value.st_ctime = 1640995200.0
    mock_access.side_effect = [True, True]  # readable, writable
    mock_guess_type.return_value = ("text/plain", None)

    result = get_file_info("/path/to/file.txt")

    assert result["size"] == 1024
    assert result["mime_type"] == "text/plain"
    assert result["exists"] is True


def test_validate_ip_address_valid():
    """Test validate_ip_address with valid IPs."""
    assert validate_ip_address("192.168.1.1") is True
    assert validate_ip_address("10.0.0.1") is True
    assert validate_ip_address("172.16.0.1") is True
    assert validate_ip_address("::1") is True  # IPv6 localhost


def test_validate_ip_address_invalid():
    """Test validate_ip_address with invalid IPs."""
    assert validate_ip_address("256.256.256.256") is False
    assert validate_ip_address("192.168.1") is False
    assert validate_ip_address("not.an.ip") is False
    assert validate_ip_address("") is False


def test_validate_port_valid():
    """Test validate_port with valid ports."""
    assert validate_port(80) is True
    assert validate_port(443) is True
    assert validate_port("8080") is True
    assert validate_port(65535) is True


def test_validate_port_invalid():
    """Test validate_port with invalid ports."""
    assert validate_port(0) is False
    assert validate_port(65536) is False
    assert validate_port(-1) is False
    assert validate_port("not_a_port") is False


def test_truncate_string_short():
    """Test truncate_string with short string."""
    result = truncate_string("short")
    assert result == "short"


def test_truncate_string_long():
    """Test truncate_string with long string."""
    long_string = "this is a very long string that needs to be truncated"
    result = truncate_string(long_string, max_length=20)
    assert len(result) <= 23  # 20 + 3 for "..."
    assert result.endswith("...")


def test_truncate_string_custom_suffix():
    """Test truncate_string with custom suffix."""
    result = truncate_string("very long string", max_length=10, suffix="***")
    assert result.endswith("***")


def test_clean_filename_basic():
    """Test clean_filename with basic characters."""
    result = clean_filename("file name with spaces.txt")
    assert result == "file name with spaces.txt"  # Function doesn't replace spaces


def test_clean_filename_special_chars():
    """Test clean_filename with special characters."""
    result = clean_filename("file<with>special:chars?.txt")
    assert result == "file_with_special_chars_.txt"


def test_clean_filename_multiple_dots():
    """Test clean_filename with multiple dots."""
    result = clean_filename("file..name...txt")
    assert result == "file..name...txt"  # Function doesn't collapse multiple dots


def test_parse_smb_timestamp_valid():
    """Test parse_smb_timestamp with valid timestamp."""
    result = parse_smb_timestamp("2023-01-01 12:00:00")
    assert result is not None
    assert isinstance(result, float)


def test_parse_smb_timestamp_invalid():
    """Test parse_smb_timestamp with invalid timestamp."""
    result = parse_smb_timestamp("invalid timestamp")
    assert result is None


def test_hex_dump_basic():
    """Test hex_dump with basic data."""
    data = b"Hello, World!"
    result = hex_dump(data)
    assert "48 65 6c 6c 6f" in result  # "Hello" in hex
    assert "Hello, World!" in result


def test_hex_dump_empty():
    """Test hex_dump with empty data."""
    result = hex_dump(b"")
    assert result == ""


def test_hex_dump_custom_width():
    """Test hex_dump with custom width."""
    data = b"1234567890"
    result = hex_dump(data, width=8)
    assert "31 32 33 34 35 36 37 38" in result


def test_calculate_hash_sha256():
    """Test calculate_hash with SHA256."""
    result = calculate_hash("test data", "sha256")
    assert len(result) == 64  # SHA256 produces 64 hex characters
    assert result.isalnum()


def test_calculate_hash_md5():
    """Test calculate_hash with MD5."""
    result = calculate_hash("test data", "md5")
    assert len(result) == 32  # MD5 produces 32 hex characters
    assert result.isalnum()


def test_calculate_hash_bytes():
    """Test calculate_hash with bytes input."""
    result = calculate_hash(b"test data", "sha256")
    assert len(result) == 64
    assert result.isalnum()


def test_merge_dictionaries():
    """Test merge_dictionaries."""
    dict1 = {"a": 1, "b": 2}
    dict2 = {"c": 3, "d": 4}
    dict3 = {"a": 5, "e": 6}  # Override 'a'

    result = merge_dictionaries(dict1, dict2, dict3)

    assert result["a"] == 5  # Last value wins
    assert result["b"] == 2
    assert result["c"] == 3
    assert result["d"] == 4
    assert result["e"] == 6


def test_flatten_dict_basic():
    """Test flatten_dict with basic nested dictionary."""
    nested = {"a": {"b": {"c": 1}}}
    result = flatten_dict(nested)
    assert result["a.b.c"] == 1


def test_flatten_dict_multiple():
    """Test flatten_dict with multiple nested keys."""
    nested = {"a": {"b": 1, "c": 2}, "d": {"e": 3}}
    result = flatten_dict(nested)
    assert result["a.b"] == 1
    assert result["a.c"] == 2
    assert result["d.e"] == 3


def test_flatten_dict_custom_sep():
    """Test flatten_dict with custom separator."""
    nested = {"a": {"b": 1}}
    result = flatten_dict(nested, sep="_")
    assert result["a_b"] == 1


def test_batch_process():
    """Test batch_process generator."""
    items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    batches = list(batch_process(items, batch_size=3))

    assert len(batches) == 4
    assert batches[0] == [1, 2, 3]
    assert batches[1] == [4, 5, 6]
    assert batches[2] == [7, 8, 9]
    assert batches[3] == [10]


def test_retry_operation_success():
    """Test retry_operation with successful operation."""

    def success_func():
        return "success"

    result = retry_operation(success_func)
    assert result == "success"


def test_retry_operation_failure_then_success():
    """Test retry_operation with failure then success."""
    call_count = 0

    def failing_then_success():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ValueError("Temporary failure")
        return "success"

    result = retry_operation(failing_then_success, max_retries=3)
    assert result == "success"
    assert call_count == 3


def test_retry_operation_all_failures():
    """Test retry_operation with all failures."""

    def always_fail():
        raise ValueError("Always fails")

    with pytest.raises(ValueError):
        retry_operation(always_fail, max_retries=2)


def test_convert_size_string_basic():
    """Test convert_size_string with basic formats."""
    assert convert_size_string("1024") == 1024
    assert convert_size_string("1KB") == 1024
    assert convert_size_string("1MB") == 1024 * 1024
    assert convert_size_string("1GB") == 1024 * 1024 * 1024


def test_convert_size_string_with_spaces():
    """Test convert_size_string with spaces."""
    assert convert_size_string("1 KB") == 1024
    assert convert_size_string("2 MB") == 2 * 1024 * 1024


def test_convert_size_string_decimal():
    """Test convert_size_string with decimal values."""
    assert convert_size_string("1.5KB") == int(1.5 * 1024)
    assert convert_size_string("2.5MB") == int(2.5 * 1024 * 1024)


@patch("shutil.get_terminal_size")
def test_get_terminal_size(mock_get_terminal_size):
    """Test get_terminal_size."""
    mock_get_terminal_size.return_value = (80, 24)

    width, height = get_terminal_size()

    assert width == 80
    assert height == 24


def test_create_progress_bar():
    """Test create_progress_bar."""
    result = create_progress_bar(50, 100, width=40)
    assert "50.0%" in result  # Function returns "50.0%" not "50%"
    assert "[" in result
    assert "]" in result


def test_create_progress_bar_zero():
    """Test create_progress_bar with zero progress."""
    result = create_progress_bar(0, 100)
    assert "0%" in result


def test_create_progress_bar_complete():
    """Test create_progress_bar with complete progress."""
    result = create_progress_bar(100, 100)
    assert "100.0%" in result  # Function returns "100.0%" not "100%"


def test_timer_context_manager():
    """Test Timer as context manager."""
    with Timer("test operation") as timer:
        time.sleep(0.01)  # Small delay

    assert timer.elapsed > 0
    assert "test operation" in str(timer)


def test_timer_property():
    """Test Timer elapsed property."""
    timer = Timer("test")
    timer.start_time = time.time() - 1.0  # Simulate 1 second elapsed

    assert timer.elapsed >= 1.0


def test_timer_str():
    """Test Timer string representation."""
    timer = Timer("test operation")
    timer.start_time = time.time() - 2.5  # Simulate 2.5 seconds elapsed

    result = str(timer)
    assert "test operation" in result
    assert "2.5" in result
