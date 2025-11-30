"""
SMB2 IOCTL handler for modular replay system.
Handles IOCTL operations including FSCTL commands using smbprotocol.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict

from ..constants import FSCTL_CONSTANTS

logger = logging.getLogger(__name__)


def handle_ioctl(replayer, op: Dict[str, Any], **kwargs):
    """Handle IOCTL operation using smbprotocol.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing IOCTL parameters
        **kwargs: Additional context (tree, session, etc.)
    """
    try:
        # Extract IOCTL parameters
        function_code = int(op.get("smb2.ioctl.function", 0))
        is_fsctl = bool(op.get("smb2.ioctl.is_fsctl", True))
        input_data = op.get("smb2.ioctl.input_data", b"")
        max_output_response = int(op.get("smb2.ioctl.max_output_response", 1024))

        # Convert input_data from hex string if needed
        if isinstance(input_data, str):
            try:
                input_data = bytes.fromhex(input_data)
            except ValueError:
                replayer.logger.warning(f"IOCTL: Invalid hex input_data: {input_data}")
                input_data = b""

        replayer.logger.debug(
            f"IOCTL: function=0x{function_code:08x}, is_fsctl={is_fsctl}, "
            f"input_len={len(input_data)}, max_output={max_output_response}"
        )

        # Handle different types of IOCTL operations
        if is_fsctl:
            result = _handle_fsctl(
                replayer, function_code, input_data, max_output_response, op, **kwargs
            )
        else:
            result = _handle_device_ioctl(
                replayer, function_code, input_data, max_output_response, op, **kwargs
            )

        if result:
            replayer.logger.info(
                f"IOCTL: Successfully completed function 0x{function_code:08x}"
            )
        else:
            replayer.logger.warning(
                f"IOCTL: No result for function 0x{function_code:08x}"
            )

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"IOCTL: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"IOCTL operation failed: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"IOCTL: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"IOCTL: Invalid parameters: {e}")
    except Exception as e:
        replayer.logger.error(f"IOCTL: Unexpected error: {e}")


def _handle_fsctl(
    replayer,
    function_code: int,
    input_data: bytes,
    max_output_response: int,
    op: Dict[str, Any],
    **kwargs,
):
    """Handle filesystem control (FSCTL) operations."""
    try:
        # Get the tree from kwargs or use the current tree
        tree = kwargs.get("tree", replayer.tree)

        if not tree:
            replayer.logger.warning("IOCTL: No tree available for FSCTL operation")
            return None

        # Handle common FSCTL operations
        if function_code == FSCTL_CONSTANTS.get(
            "FSCTL_QUERY_ALLOCATED_RANGES", 0x940CF
        ):
            return _handle_query_allocated_ranges(tree, input_data, max_output_response)
        elif function_code == FSCTL_CONSTANTS.get(
            "FSCTL_GET_NTFS_VOLUME_DATA", 0x90064
        ):
            return _handle_get_ntfs_volume_data(tree, max_output_response)
        elif function_code == FSCTL_CONSTANTS.get("FSCTL_GET_REPARSE_POINT", 0x900A8):
            return _handle_get_reparse_point(tree, input_data, max_output_response)
        elif function_code == FSCTL_CONSTANTS.get("FSCTL_SET_SPARSE", 0x900C4):
            return _handle_set_sparse(tree, input_data)
        else:
            # Use generic FSCTL for unsupported operations
            replayer.logger.debug(
                f"IOCTL: Using generic FSCTL for function 0x{function_code:08x}"
            )
            return tree.fsctl(function_code, input_data, max_output_response)

    except Exception as e:
        replayer.logger.error(
            f"FSCTL operation failed for function 0x{function_code:08x}: {e}"
        )
        return None


def _handle_device_ioctl(
    replayer,
    function_code: int,
    input_data: bytes,
    max_output_response: int,
    op: Dict[str, Any],
    **kwargs,
):
    """Handle device IOCTL operations."""
    try:
        # Get the tree from kwargs or use the current tree
        tree = kwargs.get("tree", replayer.tree)

        if not tree:
            replayer.logger.warning(
                "IOCTL: No tree available for device IOCTL operation"
            )
            return None

        # Use generic IOCTL for device operations
        replayer.logger.debug(
            f"IOCTL: Using generic device IOCTL for function 0x{function_code:08x}"
        )
        return tree.ioctl(function_code, input_data, max_output_response)

    except Exception as e:
        replayer.logger.error(
            f"Device IOCTL operation failed for function 0x{function_code:08x}: {e}"
        )
        return None


def _handle_query_allocated_ranges(tree, input_data: bytes, max_output_response: int):
    """Handle FSCTL_QUERY_ALLOCATED_RANGES."""
    try:
        # This would typically query allocated ranges for a file
        # For now, return a basic response
        return tree.fsctl(0x940CF, input_data, max_output_response)
    except Exception as e:
        logger.error(f"Query allocated ranges failed: {e}")
        return None


def _handle_get_ntfs_volume_data(tree, max_output_response: int):
    """Handle FSCTL_GET_NTFS_VOLUME_DATA."""
    try:
        # Query NTFS volume information
        return tree.fsctl(0x90064, b"", max_output_response)
    except Exception as e:
        logger.error(f"Get NTFS volume data failed: {e}")
        return None


def _handle_get_reparse_point(tree, input_data: bytes, max_output_response: int):
    """Handle FSCTL_GET_REPARSE_POINT."""
    try:
        # Get reparse point data
        return tree.fsctl(0x900A8, input_data, max_output_response)
    except Exception as e:
        logger.error(f"Get reparse point failed: {e}")
        return None


def _handle_set_sparse(tree, input_data: bytes):
    """Handle FSCTL_SET_SPARSE."""
    try:
        # Set file as sparse
        return tree.fsctl(0x900C4, input_data, 0)
    except Exception as e:
        logger.error(f"Set sparse failed: {e}")
        return None
