"""
SMB2 Oplock Break handler for modular replay system.
Handles opportunistic lock break notifications from the server.
"""
from smbprotocol.exceptions import SMBException
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Oplock Break Flags
SMB2_OPLOCK_LEVEL_II = 0x01
SMB2_OPLOCK_LEVEL_NONE = 0x02

def handle_oplock_break(replayer, op: Dict[str, Any], **kwargs):
    """Handle Oplock Break operation.
    
    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing oplock break parameters
        **kwargs: Additional context
    """
    try:
        # Extract oplock break parameters
        file_id = op.get('smb2.file_id', '')
        oplock_level = int(op.get('smb2.oplock_level', SMB2_OPLOCK_LEVEL_NONE))
        
        replayer.logger.debug(
            f"Oplock Break: file_id={file_id}, oplock_level=0x{oplock_level:02x}"
        )
        
        # Oplock break is a notification from server to client
        # In replay, this is usually a no-op, but we can log and validate
        oplock_level_desc = _get_oplock_level_description(oplock_level)
        
        replayer.logger.info(
            f"Oplock Break: Received break notification for file_id={file_id}, "
            f"new_level={oplock_level_desc} (0x{oplock_level:02x})"
        )
        
        # Validate response if expected status is available
        expected_status = op.get('smb2.nt_status', '0x00000000')
        if expected_status and expected_status != '0x00000000':
            replayer.logger.debug(f"Oplock Break: Expected status {expected_status}, got success")
            
    except SMBException as e:
        replayer.logger.error(f"Oplock Break operation failed: {e}")
        # Validate response against expected error
        expected_status = op.get('smb2.nt_status', '0x00000000')
        if expected_status and expected_status != '0x00000000':
            replayer.logger.debug(f"Oplock Break: Expected status {expected_status}, got error: {e}")
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Oplock Break: Invalid parameters: {e}")
    except Exception as e:
        replayer.logger.error(f"Oplock Break: Unexpected error: {e}")


def _get_oplock_level_description(oplock_level: int) -> str:
    """Get human-readable description of oplock level."""
    if oplock_level == SMB2_OPLOCK_LEVEL_II:
        return "SMB2_OPLOCK_LEVEL_II"
    elif oplock_level == SMB2_OPLOCK_LEVEL_NONE:
        return "SMB2_OPLOCK_LEVEL_NONE"
    else:
        return f"Unknown (0x{oplock_level:02x})"
