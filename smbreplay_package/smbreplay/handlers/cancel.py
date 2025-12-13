"""
SMB2 Cancel handler for modular replay system.
Handles operation cancellation using smbprotocol.
"""

import logging
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

        replayer.logger.debug(f"Cancel: Received cancel for message_id={message_id}")

        # SMB2 Cancel is not implemented - smbprotocol doesn't expose cancel functionality
        # and proper cancel requires tracking pending async operations with their AsyncIds.
        # Log a warning so users know this operation is skipped during replay.
        replayer.logger.warning(
            f"Cancel: Operation skipped (not implemented) for message_id={message_id}"
        )

    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Cancel: Invalid parameters: {e}")
    except Exception as e:
        replayer.logger.error(f"Cancel: Unexpected error: {e}")
