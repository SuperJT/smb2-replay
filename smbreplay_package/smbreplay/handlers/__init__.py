"""
SMB2 Replay Handlers Package

This package contains modular handlers for SMB2 operations during replay.
Each handler is responsible for executing a specific SMB2 command using smbprotocol.

Handler Status:
✅ Implemented and working

==============
✅ All remaining tasks have been moved to the MCP project management system for better tracking and organization.
"""

from .cancel import handle_cancel
from .change_notify import handle_change_notify
from .close import handle_close

# Import all handlers for easy access
from .create import handle_create
from .echo import handle_echo
from .flush import handle_flush
from .ioctl import handle_ioctl
from .lease_break import handle_lease_break
from .lock import handle_lock
from .logoff import handle_logoff
from .negotiate import handle_negotiate
from .oplock_break import handle_oplock_break
from .query_directory import handle_query_directory
from .query_info import handle_query_info
from .read import handle_read
from .response import handle_response
from .session_setup import handle_session_setup
from .set_info import handle_set_info
from .tree_connect import handle_tree_connect
from .tree_disconnect import handle_tree_disconnect
from .write import handle_write

__all__ = [
    "handle_create",
    "handle_read",
    "handle_write",
    "handle_close",
    "handle_lock",
    "handle_set_info",
    "handle_tree_connect",
    "handle_tree_disconnect",
    "handle_session_setup",
    "handle_logoff",
    "handle_negotiate",
    "handle_echo",
    "handle_flush",
    "handle_ioctl",
    "handle_query_directory",
    "handle_query_info",
    "handle_change_notify",
    "handle_cancel",
    "handle_oplock_break",
    "handle_lease_break",
    "handle_response",
]
