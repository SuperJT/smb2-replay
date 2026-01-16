"""
SMB2 Set Info handler for modular replay system.
Sets file information using smbprotocol Open object.
Handles EOF/allocation size setting for file size operations.
"""

import logging
import struct
from typing import Any

from smbprotocol.exceptions import SMBException

logger = logging.getLogger(__name__)


def handle_set_info(replayer, op: dict[str, Any], **kwargs):
    """Handle Set Info operation using smbprotocol Open object.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing set info parameters
        **kwargs: Additional context
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)

    if not file_open:
        replayer.logger.warning(f"Set Info: No mapping found for fid {original_fid}")
        return

    try:
        # Extract info_type, file_info_class, and additional_information from op
        info_type = int(op.get("smb2.setinfo.info_type", 0))
        file_info_class = int(op.get("smb2.setinfo.file_info_class", 0))
        additional_information = int(op.get("smb2.setinfo.additional_information", 0))
        
        # Check if this is a file size operation (class 19 or 20)
        buffer = None
        if info_type == 1 and file_info_class in [19, 20]:
            # File size operation - construct buffer from smb2.eof field
            eof_str = op.get("smb2.eof")
            if eof_str:
                try:
                    eof_value = int(eof_str)
                    # Pack as 8-byte little-endian (Q = unsigned long long)
                    buffer = struct.pack('<Q', eof_value)
                    replayer.logger.debug(
                        f"Set Info: Constructed EOF buffer for fid={original_fid}, eof={eof_value}"
                    )
                except (ValueError, TypeError) as e:
                    replayer.logger.error(
                        f"Set Info: Failed to parse EOF value '{eof_str}' for fid {original_fid}: {e}"
                    )
                    return
        
        # If not a file size operation or EOF parsing failed, try to get buffer from op
        if buffer is None:
            buffer = op.get("smb2.setinfo.buffer", b"")
            if isinstance(buffer, str):
                try:
                    buffer = bytes.fromhex(buffer)  # If buffer is hex string
                except ValueError:
                    replayer.logger.warning(
                        f"Set Info: Invalid hex buffer for fid {original_fid}, skipping"
                    )
                    return

        file_open.set_info(
            info_type=info_type,
            file_info_class=file_info_class,
            additional_information=additional_information,
            buffer=buffer,
        )
        replayer.logger.info(
            f"Set Info: fid={original_fid}, info_type={info_type}, file_info_class={file_info_class}, "
            f"additional_information={additional_information}, buffer_len={len(buffer)}"
        )
    except SMBException as e:
        replayer.logger.error(f"Set Info failed for fid {original_fid}: {e}")
    except (ValueError, TypeError) as e:
        replayer.logger.error(
            f"Set Info: Invalid parameters for fid {original_fid}: {e}"
        )
    except Exception as e:
        replayer.logger.error(f"Set Info: Unexpected error for fid {original_fid}: {e}")
