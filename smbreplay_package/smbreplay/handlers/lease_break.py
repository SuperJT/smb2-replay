"""
SMB3 Lease Break Handler for modular replay system.
Handles SMB2_LEASE_BREAK (0x13) operations for SMB3 replay.
"""

import logging
from typing import Any

from smbprotocol.exceptions import SMBException

logger = logging.getLogger(__name__)

# Lease Break Flags
SMB2_LEASE_BREAK_ACK_FLAG_ACK_REQUIRED = 0x01


def handle_lease_break(replayer, op: dict[str, Any], **kwargs):
    """Handle SMB2_LEASE_BREAK operation (SMB3).

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing lease break parameters
        **kwargs: Additional context
    """
    try:
        # Extract lease break parameters
        lease_key = op.get("smb2.lease_key", "")
        current_lease_state = int(op.get("smb2.current_lease_state", 0))
        new_lease_state = int(op.get("smb2.new_lease_state", 0))
        break_reason = int(op.get("smb2.break_reason", 0))
        # Note: access_mask_hint and share_mask_hint are available but not used in current implementation

        replayer.logger.debug(
            f"Lease Break: lease_key={lease_key}, current_state=0x{current_lease_state:04x}, "
            f"new_state=0x{new_lease_state:04x}, break_reason=0x{break_reason:02x}"
        )

        # SMB2_LEASE_BREAK is a notification from server to client
        # In replay, this is usually a no-op, but we can log and validate
        current_state_desc = _get_lease_state_description(current_lease_state)
        new_state_desc = _get_lease_state_description(new_lease_state)
        break_reason_desc = _get_break_reason_description(break_reason)

        replayer.logger.info(
            f"Lease Break: Received break notification for lease_key={lease_key}, "
            f"current_state={current_state_desc}, new_state={new_state_desc}, "
            f"break_reason={break_reason_desc}"
        )

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Lease Break: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Lease Break operation failed: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Lease Break: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Lease Break: Invalid parameters: {e}")
    except Exception as e:
        replayer.logger.error(f"Lease Break: Unexpected error: {e}")


def _get_lease_state_description(lease_state: int) -> str:
    """Get human-readable description of lease state."""
    states = []
    if lease_state & 0x0001:
        states.append("SMB2_LEASE_READ_CACHING")
    if lease_state & 0x0002:
        states.append("SMB2_LEASE_HANDLE_CACHING")
    if lease_state & 0x0004:
        states.append("SMB2_LEASE_WRITE_CACHING")

    if states:
        return " | ".join(states)
    else:
        return f"None (0x{lease_state:04x})"


def _get_break_reason_description(break_reason: int) -> str:
    """Get human-readable description of break reason."""
    if break_reason == 0x01:
        return "SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED"
    elif break_reason == 0x02:
        return "SMB2_NOTIFY_BREAK_LEASE_FLAG_BREAK_IN_PROGRESS"
    else:
        return f"Unknown (0x{break_reason:02x})"
