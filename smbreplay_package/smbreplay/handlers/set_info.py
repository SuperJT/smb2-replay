"""
SMB2 Set Info handler for modular replay system.
Sets file information using smbprotocol Open object.
"""
from smbprotocol.exceptions import SMBException
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

def handle_set_info(replayer, op: Dict[str, Any], **kwargs):
    """Handle Set Info operation using smbprotocol Open object.
    
    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing set info parameters
        **kwargs: Additional context
    """
    original_fid = op.get('smb2.fid', '')
    file_open = replayer.fid_mapping.get(original_fid)

    if not file_open:
        replayer.logger.warning(f"Set Info: No mapping found for fid {original_fid}")
        return

    try:
        # Extract info_type, file_info_class, buffer, and additional_information from op
        info_type = int(op.get('smb2.setinfo.info_type', 0))
        file_info_class = int(op.get('smb2.setinfo.file_info_class', 0))
        additional_information = int(op.get('smb2.setinfo.additional_information', 0))
        buffer = op.get('smb2.setinfo.buffer', b'')
        if isinstance(buffer, str):
            buffer = bytes.fromhex(buffer)  # If buffer is hex string

        file_open.set_info(
            info_type=info_type,
            file_info_class=file_info_class,
            additional_information=additional_information,
            buffer=buffer
        )
        replayer.logger.info(
            f"Set Info: fid={original_fid}, info_type={info_type}, file_info_class={file_info_class}, "
            f"additional_information={additional_information}, buffer_len={len(buffer)}"
        )
    except SMBException as e:
        replayer.logger.error(f"Set Info failed for fid {original_fid}: {e}")
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Set Info: Invalid parameters for fid {original_fid}: {e}")
    except Exception as e:
        replayer.logger.error(f"Set Info: Unexpected error for fid {original_fid}: {e}")