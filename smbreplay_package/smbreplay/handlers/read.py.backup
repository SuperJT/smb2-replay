"""
SMB2 Read handler for modular replay system.
Reads data from the mapped Open object for the given FID using smbprotocol.
"""
from smbprotocol.exceptions import SMBException

def handle_read(replayer, op):
    """Handle Read operation using smbprotocol Open object.
    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    original_fid = op.get('smb2.fid', '')
    file_open = replayer.fid_mapping.get(original_fid)
    if file_open:
        offset = int(op.get('smb2.read.offset', 0))
        length = int(op.get('smb2.read.length', 1024))
        try:
            data = file_open.read(length, offset)
            replayer.logger.debug(f"Read: fid={original_fid}, offset={offset}, length={length}, data_length={len(data) if data else 0}")
        except SMBException as e:
            replayer.logger.error(f"Read failed for fid {original_fid}: {e}")
    else:
        replayer.logger.warning(f"Read: No mapping found for fid {original_fid}")
