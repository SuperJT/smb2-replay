"""
SMB2 Flush handler for modular replay system.
Flushes file data to disk using smbprotocol Open object.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict

logger = logging.getLogger(__name__)


def handle_flush(replayer, op: Dict[str, Any], **kwargs):
    """Handle Flush operation using smbprotocol Open object.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing flush parameters
        **kwargs: Additional context
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)

    if not file_open:
        replayer.logger.warning(f"Flush: No mapping found for fid {original_fid}")
        return

    try:
        # Flush the file to ensure all data is written to disk
        file_open.flush()
        replayer.logger.info(f"Flush: Successfully flushed file for fid {original_fid}")

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Flush: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Flush failed for fid {original_fid}: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Flush: Expected status {expected_status}, got error: {e}"
            )
    except Exception as e:
        replayer.logger.error(f"Flush: Unexpected error for fid {original_fid}: {e}")
