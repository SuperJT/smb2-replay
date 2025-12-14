import logging

logger = logging.getLogger(__name__)


def handle_response(replayer, op, cmd):
    """Handle response operations to update mappings.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
        cmd: Command code
    """
    if cmd == 3:  # Tree Connect response
        original_tid = op.get("smb2.tid", "")
        if replayer.state["last_new_tid"] is not None:
            replayer.tid_mapping[original_tid] = replayer.state["last_new_tid"]
            logger.debug(
                f"Mapped tid {original_tid} to {replayer.state['last_new_tid']}"
            )
            replayer.state["last_new_tid"] = None
    elif cmd == 5:  # Create response
        original_fid = op.get("smb2.fid", "")
        if replayer.state["last_new_fid"] is not None:
            replayer.fid_mapping[original_fid] = replayer.state["last_new_fid"]
            logger.debug(
                f"Mapped fid {original_fid} to {replayer.state['last_new_fid']}"
            )
            replayer.state["last_new_fid"] = None
