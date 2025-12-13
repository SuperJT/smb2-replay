"""
SMB2 Query Directory handler for modular replay system.
Queries directory contents and file information using smbprotocol Open object.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict, Optional

from ..constants import FILE_INFO_CLASSES, SMB2_QUERY_DIRECTORY_FLAGS

logger = logging.getLogger(__name__)


def handle_query_directory(replayer, op: Dict[str, Any], **kwargs):
    """Handle Query Directory operation using smbprotocol Open object.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing query directory parameters
        **kwargs: Additional context (tree, session, etc.)

    Supported File Info Classes:
        - FILE_DIRECTORY_INFORMATION: Basic directory information
        - FILE_FULL_DIRECTORY_INFORMATION: Full directory information
        - FILE_BOTH_DIRECTORY_INFORMATION: Both directory information
        - FILENAMES_INFORMATION: File names only
        - FILEID_BOTH_DIRECTORY_INFORMATION: Both with file IDs
        - FILEID_FULL_DIRECTORY_INFORMATION: Full with file IDs

    Query Directory Features:
        - Pattern matching (wildcards)
        - Restart scans
        - Single entry returns
        - Index specification
        - Directory reopening
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)

    if not file_open:
        replayer.logger.warning(
            f"Query Directory: No mapping found for fid {original_fid}"
        )
        return

    try:
        # Extract query directory parameters
        file_info_class = int(
            op.get(
                "smb2.querydirectory.file_info_class",
                FILE_INFO_CLASSES["FILE_DIRECTORY_INFORMATION"],
            )
        )
        flags = int(op.get("smb2.querydirectory.flags", 0))
        file_index = int(op.get("smb2.querydirectory.file_index", 0))
        output_buffer_length = int(
            op.get("smb2.querydirectory.output_buffer_length", 1024)
        )
        file_name = op.get("smb2.querydirectory.file_name", "*")

        # Handle different query patterns
        if not file_name or file_name == "":
            file_name = "*"  # Default to all files

        # Determine query behavior based on flags
        restart_scan = bool(flags & SMB2_QUERY_DIRECTORY_FLAGS["SMB2_RESTART_SCANS"])
        return_single_entry = bool(
            flags & SMB2_QUERY_DIRECTORY_FLAGS["SMB2_RETURN_SINGLE_ENTRY"]
        )
        index_specified = bool(
            flags & SMB2_QUERY_DIRECTORY_FLAGS["SMB2_INDEX_SPECIFIED"]
        )
        _reopen = bool(flags & SMB2_QUERY_DIRECTORY_FLAGS["SMB2_REOPEN"])  # noqa: F841

        replayer.logger.debug(
            f"Query Directory: fid={original_fid}, file_info_class={file_info_class}, "
            f"file_name='{file_name}', flags=0x{flags:02x}, file_index={file_index}"
        )

        # Execute the directory query
        result = _query_directory_info(
            file_open,
            file_info_class,
            file_name,
            output_buffer_length,
            restart_scan=restart_scan,
            return_single_entry=return_single_entry,
            file_index=file_index if index_specified else None,
        )

        if result:
            replayer.logger.info(
                f"Query Directory: fid={original_fid}, returned {len(result)} entries, "
                f"pattern='{file_name}', class={file_info_class}"
            )
        else:
            replayer.logger.info(
                f"Query Directory: fid={original_fid}, no entries found for pattern '{file_name}'"
            )

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Query Directory: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Query Directory failed for fid {original_fid}: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Query Directory: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(
            f"Query Directory: Invalid parameters for fid {original_fid}: {e}"
        )
    except Exception as e:
        replayer.logger.error(
            f"Query Directory: Unexpected error for fid {original_fid}: {e}"
        )


def _query_directory_info(
    file_open,
    file_info_class: int,
    file_name: str,
    output_buffer_length: int,
    restart_scan: bool = False,
    return_single_entry: bool = False,
    file_index: Optional[int] = None,
):
    """Query directory information with specified parameters."""
    try:
        # Use the appropriate query method based on file info class
        if file_info_class == FILE_INFO_CLASSES["FILE_DIRECTORY_INFORMATION"]:
            return file_open.query_directory_info(
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
        elif file_info_class == FILE_INFO_CLASSES["FILE_FULL_DIRECTORY_INFORMATION"]:
            return file_open.query_full_directory_info(
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
        elif file_info_class == FILE_INFO_CLASSES["FILE_BOTH_DIRECTORY_INFORMATION"]:
            return file_open.query_both_directory_info(
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
        elif file_info_class == FILE_INFO_CLASSES["FILENAMES_INFORMATION"]:
            return file_open.query_names_info(
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
        elif file_info_class == FILE_INFO_CLASSES["FILEID_BOTH_DIRECTORY_INFORMATION"]:
            return file_open.query_id_both_directory_info(
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
        elif file_info_class == FILE_INFO_CLASSES["FILEID_FULL_DIRECTORY_INFORMATION"]:
            return file_open.query_id_full_directory_info(
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
        else:
            # Use generic query for unsupported classes
            logger.warning(
                f"Query Directory: Unsupported file info class {file_info_class}, using generic query"
            )
            return file_open.query_directory(
                file_info_class,
                file_name,
                output_buffer_length,
                restart_scan=restart_scan,
                return_single_entry=return_single_entry,
                file_index=file_index,
            )
    except SMBException as e:
        logger.error(f"Directory query failed for class {file_info_class}: {e}")
        return None
