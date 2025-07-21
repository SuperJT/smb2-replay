# NOTE: SMB2/3 locking support requires the latest smbprotocol from GitHub.
# Install with: pip install --upgrade git+https://github.com/jborean93/smbprotocol.git

from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open, SMB2LockElement

import logging

logger = logging.getLogger(__name__)

def handle_lock(self, op):
    """Handle Lock operation using smbprotocol.

    Args:
        op: Operation dictionary
    """
    original_fid = op.get('smb2.fid', '')
    file_open = self.fid_mapping.get(original_fid)

    logger.info(f"handle_lock called for fid={original_fid}, op={op}")

    if file_open:
        try:
            # Parse lock parameters from op
            lock_sequence = int(op.get('smb2.lock.sequence', 0))
            lock_count = int(op.get('smb2.lock.count', 1))
            lock_elements = op.get('smb2.lock_elements', [])
            # Add debug: show all keys in op
            logger.debug(f"Available keys in op: {list(op.keys())}")
            # If lock_elements is not present, try to build from offset/length/flags using correct DataFrame field names
            if not lock_elements:
                # Try new field names first
                offset = op.get('smb2.lock_offset')
                length = op.get('smb2.lock_length')
                raw_flags = op.get('smb2.lock_flags')
                # Fallback to legacy field names if not present
                if offset is None:
                    offset = op.get('smb2.lock.offset', 0)
                if length is None:
                    length = op.get('smb2.lock.length', 0)
                if raw_flags is None:
                    raw_flags = op.get('smb2.lock.flags', 0)
                logger.debug(f"Lock field values: offset={offset}, length={length}, flags={raw_flags}")
                try:
                    offset = int(offset)
                except Exception:
                    offset = 0
                try:
                    length = int(length)
                except Exception:
                    length = 0
                try:
                    flags = int(raw_flags, 0) if isinstance(raw_flags, str) else int(raw_flags)
                except Exception as e:
                    logger.warning(f"Could not parse lock flags '{raw_flags}', defaulting to 0: {e}")
                    import pprint
                    logger.error(f"Full operation for problematic lock: {pprint.pformat(op)}")
                    flags = 0
                lock_elements = [(offset, length, flags)]
            logger.info(f"Lock elements for fid={original_fid}: {lock_elements}")
            if not lock_elements:
                logger.warning(f"No lock elements found in op: {op}")
                return
            # Build SMB2LockElement objects
            smb2_locks = []
            for offset, length, flags in lock_elements:
                lock_elem = SMB2LockElement()
                lock_elem['offset'] = offset
                lock_elem['length'] = length
                # Set the flags field directly from the trace
                lock_elem['flags'] = flags
                smb2_locks.append(lock_elem)
            file_open.lock(smb2_locks)
            logger.info(f"Lock command(s) sent for fid={original_fid}, count={len(smb2_locks)}")
        except SMBException as e:
            logger.error(f"Lock failed for fid {original_fid}: {e}")
    else:
        logger.warning(f"Lock: No mapping found for fid {original_fid}, lock command not sent.")
