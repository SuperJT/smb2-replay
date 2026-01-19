# NOTE: SMB2/3 locking support requires the latest smbprotocol from GitHub.
# Install with: pip install --upgrade git+https://github.com/jborean93/smbprotocol.git

"""
SMB2 Lock handler for modular replay system.
Applies file locks using smbprotocol Open object.
"""

import logging
from typing import Any

from smbprotocol.exceptions import SMBException

# Try to import SMB2LockElement - only available in GitHub version
try:
    from smbprotocol.open import SMB2LockElement

    LOCK_SUPPORT_AVAILABLE = True
except ImportError:
    LOCK_SUPPORT_AVAILABLE = False
    SMB2LockElement = None

logger = logging.getLogger(__name__)


class LockNotSupportedError(Exception):
    """Raised when lock operations are not supported due to missing dependencies."""

    pass


def handle_lock(replayer, op: dict[str, Any], **kwargs):
    """Handle Lock operation using smbprotocol Open object.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary containing lock parameters
        **kwargs: Additional context

    Raises:
        LockNotSupportedError: If smbprotocol lock support is not available
    """
    if not LOCK_SUPPORT_AVAILABLE:
        msg = (
            "Lock operations require smbprotocol from GitHub. "
            "Install with: pip install --upgrade git+https://github.com/jborean93/smbprotocol.git"
        )
        replayer.logger.error(msg)
        raise LockNotSupportedError(msg)

    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)

    replayer.logger.info(f"handle_lock called for fid={original_fid}, op={op}")

    if not file_open:
        replayer.logger.warning(
            f"Lock: No mapping found for fid {original_fid}, lock command not sent."
        )
        return

    try:
        # Parse lock parameters from op
        # Note: lock_sequence and lock_count are available but not used in current implementation
        lock_elements = op.get("smb2.lock_elements", [])
        # Add debug: show all keys in op
        replayer.logger.debug(f"Available keys in op: {list(op.keys())}")
        # If lock_elements is not present, try to build from offset/length/flags using correct DataFrame field names
        if not lock_elements:
            # tshark uses smb2.file_offset for lock offset (no smb2.lock_offset field exists)
            offset = op.get("smb2.file_offset")
            length = op.get("smb2.lock_length")
            raw_flags = op.get("smb2.lock_flags")
            # Fallback to legacy field names if not present
            if offset is None:
                offset = op.get("smb2.lock_offset", 0)  # Fallback for compatibility
            if length is None:
                length = op.get("smb2.lock.length", 0)
            if raw_flags is None:
                raw_flags = op.get("smb2.lock.flags", 0)

            # Handle array-wrapped values (tshark sometimes returns values as arrays)
            if isinstance(offset, (list, tuple)):
                offset = offset[0] if offset else 0
            if isinstance(length, (list, tuple)):
                length = length[0] if length else 0
            if isinstance(raw_flags, (list, tuple)):
                raw_flags = raw_flags[0] if raw_flags else 0

            replayer.logger.debug(
                f"Lock field values: offset={offset}, length={length}, flags={raw_flags}"
            )
            try:
                # Handle string values (including hex strings)
                if isinstance(offset, str):
                    offset = offset.strip()
                    if offset.startswith("0x") or offset.startswith("0X"):
                        offset = int(offset, 16)
                    else:
                        offset = int(offset)
                else:
                    offset = int(offset) if offset is not None else 0
            except Exception:
                replayer.logger.warning(f"Could not parse lock offset '{offset}', defaulting to 0")
                offset = 0
            try:
                if isinstance(length, str):
                    length = length.strip()
                    if length.startswith("0x") or length.startswith("0X"):
                        length = int(length, 16)
                    else:
                        length = int(length)
                else:
                    length = int(length) if length is not None else 0
            except Exception:
                replayer.logger.warning(f"Could not parse lock length '{length}', defaulting to 0")
                length = 0
            try:
                if isinstance(raw_flags, str):
                    raw_flags = raw_flags.strip()
                    if raw_flags.startswith("0x") or raw_flags.startswith("0X"):
                        flags = int(raw_flags, 16)
                    else:
                        flags = int(raw_flags)
                else:
                    flags = int(raw_flags) if raw_flags is not None else 0
            except Exception as e:
                replayer.logger.warning(
                    f"Could not parse lock flags '{raw_flags}', defaulting to 0: {e}"
                )
                flags = 0
            lock_elements = [(offset, length, flags)]
        replayer.logger.info(f"Lock elements for fid={original_fid}: {lock_elements}")
        if not lock_elements:
            replayer.logger.warning(f"No lock elements found in op: {op}")
            return
        # Build SMB2LockElement objects
        smb2_locks = []
        for offset, length, flags in lock_elements:
            lock_elem = SMB2LockElement()
            lock_elem["offset"] = offset
            lock_elem["length"] = length
            # Set the flags field directly from the trace
            lock_elem["flags"] = flags
            smb2_locks.append(lock_elem)
        file_open.lock(smb2_locks)
        replayer.logger.info(
            f"Lock command(s) sent for fid={original_fid}, count={len(smb2_locks)}"
        )
    except SMBException as e:
        replayer.logger.error(f"Lock failed for fid {original_fid}: {e}")
    except (ValueError, TypeError) as e:
        replayer.logger.error(f"Lock: Invalid parameters for fid {original_fid}: {e}")
    except Exception as e:
        replayer.logger.error(f"Lock: Unexpected error for fid {original_fid}: {e}")
