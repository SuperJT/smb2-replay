"""
SMB2 Query Info handler for modular replay system.
Queries file information using smbprotocol Open object.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict

from ..constants import SMB2_FILE_INFO_CLASSES, SMB2_INFO_LEVELS

logger = logging.getLogger(__name__)


def handle_query_info(replayer, op: Dict[str, Any], **kwargs):
    """Handle Query Info operation using smbprotocol Open object.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing query info parameters
        **kwargs: Additional context (tree, session, etc.)

    Supported Info Types:
        - SMB2_0_INFO_FILE: Query file information
        - SMB2_0_INFO_FILESYSTEM: Query filesystem information
        - SMB2_0_INFO_SECURITY: Query security information
        - SMB2_0_INFO_QUOTA: Query quota information

    Common File Info Classes:
        - SMB2_FILE_BASIC_INFO: Basic file attributes
        - SMB2_FILE_STANDARD_INFO: Standard file information
        - SMB2_FILE_NAME_INFO: File name information
        - SMB2_FILE_STREAM_INFO: File stream information
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)

    if not file_open:
        replayer.logger.warning(f"Query Info: No mapping found for fid {original_fid}")
        return

    try:
        # Extract query info parameters
        info_type = int(
            op.get("smb2.queryinfo.info_type", SMB2_INFO_LEVELS["SMB2_0_INFO_FILE"])
        )
        file_info_class = int(
            op.get(
                "smb2.queryinfo.file_info_class",
                SMB2_FILE_INFO_CLASSES["SMB2_FILE_BASIC_INFO"],
            )
        )
        output_buffer_length = int(op.get("smb2.queryinfo.output_buffer_length", 1024))
        additional_information = int(op.get("smb2.queryinfo.additional_information", 0))

        # Handle different info types
        if info_type == SMB2_INFO_LEVELS["SMB2_0_INFO_FILE"]:
            result = _query_file_info(
                file_open, file_info_class, output_buffer_length, additional_information
            )
        elif info_type == SMB2_INFO_LEVELS["SMB2_0_INFO_FILESYSTEM"]:
            result = _query_filesystem_info(
                file_open, file_info_class, output_buffer_length
            )
        elif info_type == SMB2_INFO_LEVELS["SMB2_0_INFO_SECURITY"]:
            result = _query_security_info(
                file_open, file_info_class, output_buffer_length, additional_information
            )
        elif info_type == SMB2_INFO_LEVELS["SMB2_0_INFO_QUOTA"]:
            result = _query_quota_info(file_open, file_info_class, output_buffer_length)
        else:
            replayer.logger.warning(f"Query Info: Unsupported info type {info_type}")
            return

        replayer.logger.info(
            f"Query Info: fid={original_fid}, info_type={info_type}, "
            f"file_info_class={file_info_class}, result_size={len(result) if result else 0}"
        )

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Query Info: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Query Info failed for fid {original_fid}: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Query Info: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(
            f"Query Info: Invalid parameters for fid {original_fid}: {e}"
        )
    except Exception as e:
        replayer.logger.error(
            f"Query Info: Unexpected error for fid {original_fid}: {e}"
        )


def _query_file_info(
    file_open,
    file_info_class: int,
    output_buffer_length: int,
    additional_information: int = 0,
):
    """Query file information."""
    try:
        if file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_BASIC_INFO"]:
            return file_open.query_basic_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_STANDARD_INFO"]:
            return file_open.query_standard_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_EA_INFO"]:
            return file_open.query_ea_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_NAME_INFO"]:
            return file_open.query_name_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_ALLOCATION_INFO"]:
            return file_open.query_allocation_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_END_OF_FILE_INFO"]:
            return file_open.query_eof_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_STREAM_INFO"]:
            return file_open.query_stream_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILE_COMPRESSION_INFO"]:
            return file_open.query_compression_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_ATTRIBUTE_TAG_INFO"]:
            return file_open.query_attribute_tag_info()
        else:
            # Use generic query for unsupported classes
            return file_open.query_info(file_info_class, output_buffer_length)
    except SMBException as e:
        logger.error(f"File info query failed for class {file_info_class}: {e}")
        return None


def _query_filesystem_info(file_open, file_info_class: int, output_buffer_length: int):
    """Query filesystem information."""
    try:
        if file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_VOLUME_INFO"]:
            return file_open.query_fs_volume_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_LABEL_INFO"]:
            return file_open.query_fs_label_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_SIZE_INFO"]:
            return file_open.query_fs_size_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_DEVICE_INFO"]:
            return file_open.query_fs_device_info()
        elif (
            file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_ATTRIBUTE_INFO"]
        ):
            return file_open.query_fs_attribute_info()
        elif file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_CONTROL_INFO"]:
            return file_open.query_fs_control_info()
        elif (
            file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_FULL_SIZE_INFO"]
        ):
            return file_open.query_fs_full_size_info()
        elif (
            file_info_class == SMB2_FILE_INFO_CLASSES["SMB2_FILESYSTEM_OBJECT_ID_INFO"]
        ):
            return file_open.query_fs_object_id_info()
        else:
            # Use generic query for unsupported classes
            return file_open.query_fs_info(file_info_class, output_buffer_length)
    except SMBException as e:
        logger.error(f"Filesystem info query failed for class {file_info_class}: {e}")
        return None


def _query_security_info(
    file_open,
    file_info_class: int,
    output_buffer_length: int,
    additional_information: int = 0,
):
    """Query security information."""
    try:
        # Security info classes are bit flags
        security_info = (
            additional_information if additional_information else 0x00000001
        )  # OWNER_SECURITY_INFORMATION
        return file_open.query_security_info(security_info, output_buffer_length)
    except SMBException as e:
        logger.error(f"Security info query failed: {e}")
        return None


def _query_quota_info(file_open, file_info_class: int, output_buffer_length: int):
    """Query quota information."""
    try:
        # Quota queries are not commonly supported, log as unsupported
        logger.warning(f"Quota info query not implemented for class {file_info_class}")
        return None
    except SMBException as e:
        logger.error(f"Quota info query failed: {e}")
        return None
