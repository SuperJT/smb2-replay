"""
SMB2 Write handler for modular replay system.
Writes data to the mapped Open object for the given FID using smbprotocol.
"""
from smbprotocol.exceptions import SMBException

def handle_write(replayer, op):
    """Handle Write operation using smbprotocol Open object.
    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    original_fid = op.get('smb2.fid', '')
    file_open = replayer.fid_mapping.get(original_fid)
    if file_open:
        offset = int(op.get('smb2.write.offset', 0))
        data = bytes.fromhex(op.get('smb2.write_data', '')) if op.get('smb2.write_data') else b'test_data'
        try:
            bytes_written = file_open.write(data, offset)
            replayer.logger.debug(f"Write: fid={original_fid}, offset={offset}, data_length={len(data)}, bytes_written={bytes_written}")
        except SMBException as e:
            replayer.logger.error(f"Write failed for fid {original_fid}: {e}")
    else:
        replayer.logger.warning(f"Write: No mapping found for fid {original_fid}")
