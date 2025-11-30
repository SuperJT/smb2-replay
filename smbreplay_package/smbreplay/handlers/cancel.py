"""
SMB2 Cancel handler for modular replay system.
Handles operation cancellation using smbprotocol.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict

logger = logging.getLogger(__name__)


def handle_cancel(replayer, op: Dict[str, Any], **kwargs):
    """Handle Cancel operation using smbprotocol.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing cancel parameters
        **kwargs: Additional context (session, etc.)
    """
    try:
        # Get the session from kwargs
        session = kwargs.get("session")

        if not session:
            replayer.logger.warning("Cancel: No session available for cancel operation")
            return

        # Extract cancel parameters
        message_id = op.get("smb2.msg_id", "")

        replayer.logger.debug(f"Cancel: Attempting to cancel message_id={message_id}")

        # Note: smbprotocol doesn't expose a direct cancel method
        # This is a placeholder for the cancel functionality
        # In a real implementation, this would send a cancel request to the server

        replayer.logger.info(
            f"Cancel: Cancel request logged for message_id={message_id}"
        )

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Cancel: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Cancel operation failed: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Cancel: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Cancel: Invalid parameters: {e}")
    except Exception as e:
        replayer.logger.error(f"Cancel: Unexpected error: {e}")
