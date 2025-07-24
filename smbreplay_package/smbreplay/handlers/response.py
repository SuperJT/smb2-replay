import logging

logger = logging.getLogger(__name__)


def handle_response(self, op, cmd):
    """Handle response operations to update mappings."""
    if cmd == 3:  # Tree Connect response
        original_tid = op.get("smb2.tid", "")
        if self.state["last_new_tid"] is not None:
            self.tid_mapping[original_tid] = self.state["last_new_tid"]
            logger.debug(f"Mapped tid {original_tid} to {self.state['last_new_tid']}")
            self.state["last_new_tid"] = None
    elif cmd == 5:  # Create response
        original_fid = op.get("smb2.fid", "")
        if self.state["last_new_fid"] is not None:
            self.fid_mapping[original_fid] = self.state["last_new_fid"]
            logger.debug(f"Mapped fid {original_fid} to {self.state['last_new_fid']}")
            self.state["last_new_fid"] = None
