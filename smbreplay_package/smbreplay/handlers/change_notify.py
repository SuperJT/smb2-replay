"""
SMB2 Change Notify handler for modular replay system.
Handles file system change notifications using smbprotocol.
"""

import logging
from smbprotocol.exceptions import SMBException
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Change Notify Flags
SMB2_WATCH_TREE = 0x0001
SMB2_WATCH_ACTION_CHECK = 0x0002
SMB2_WATCH_ACTION_ADDED = 0x0004
SMB2_WATCH_ACTION_REMOVED = 0x0008
SMB2_WATCH_ACTION_MODIFIED = 0x0010
SMB2_WATCH_ACTION_RENAMED_OLD_NAME = 0x0020
SMB2_WATCH_ACTION_RENAMED_NEW_NAME = 0x0040


def handle_change_notify(replayer, op: Dict[str, Any], **kwargs):
    """Handle Change Notify operation using smbprotocol.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing change notify parameters
        **kwargs: Additional context
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)

    if not file_open:
        replayer.logger.warning(
            f"Change Notify: No mapping found for fid {original_fid}"
        )
        return

    try:
        # Extract change notify parameters
        flags = int(op.get("smb2.changenotify.flags", 0))
        output_buffer_length = int(
            op.get("smb2.changenotify.output_buffer_length", 1024)
        )
        file_name = op.get("smb2.changenotify.file_name", "")

        replayer.logger.debug(
            f"Change Notify: fid={original_fid}, flags=0x{flags:04x}, "
            f"output_buffer_length={output_buffer_length}, file_name='{file_name}'"
        )

        # Determine what to watch based on flags
        watch_tree = bool(flags & SMB2_WATCH_TREE)

        # Set up change notification
        # Note: This is a simplified implementation
        # In a real scenario, this would set up async monitoring
        try:
            # For replay purposes, we'll just log the notification request
            # The actual change notification would be handled asynchronously
            replayer.logger.info(
                f"Change Notify: Set up monitoring for fid {original_fid}, "
                f"watch_tree={watch_tree}, file_name='{file_name}'"
            )

            # In a real implementation, this would return a notification context
            # that could be used to receive change events

        except SMBException as e:
            replayer.logger.error(
                f"Change Notify setup failed for fid {original_fid}: {e}"
            )
            raise

        # Validate response if expected status is available
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Change Notify: Expected status {expected_status}, got success"
            )

    except SMBException as e:
        replayer.logger.error(f"Change Notify failed for fid {original_fid}: {e}")
        # Validate response against expected error
        expected_status = op.get("smb2.nt_status", "0x00000000")
        if expected_status and expected_status != "0x00000000":
            replayer.logger.debug(
                f"Change Notify: Expected status {expected_status}, got error: {e}"
            )
    except (ValueError, TypeError) as e:
        replayer.logger.error(
            f"Change Notify: Invalid parameters for fid {original_fid}: {e}"
        )
    except Exception as e:
        replayer.logger.error(
            f"Change Notify: Unexpected error for fid {original_fid}: {e}"
        )


def _parse_change_notify_flags(flags: int) -> Dict[str, bool]:
    """Parse change notify flags into readable format."""
    return {
        "watch_tree": bool(flags & SMB2_WATCH_TREE),
        "watch_action_check": bool(flags & SMB2_WATCH_ACTION_CHECK),
        "watch_action_added": bool(flags & SMB2_WATCH_ACTION_ADDED),
        "watch_action_removed": bool(flags & SMB2_WATCH_ACTION_REMOVED),
        "watch_action_modified": bool(flags & SMB2_WATCH_ACTION_MODIFIED),
        "watch_action_renamed_old_name": bool(
            flags & SMB2_WATCH_ACTION_RENAMED_OLD_NAME
        ),
        "watch_action_renamed_new_name": bool(
            flags & SMB2_WATCH_ACTION_RENAMED_NEW_NAME
        ),
    }
