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
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)
    if file_open:
        offset = int(op.get("smb2.write.offset", 0))
        write_data_hex = op.get("smb2.write_data")
        if not write_data_hex:
            replayer.logger.error(
                f"Write: No data provided for fid {original_fid} - cannot write without data"
            )
            return
        try:
            data = bytes.fromhex(write_data_hex)
        except ValueError as e:
            replayer.logger.error(
                f"Write: Invalid hex data for fid {original_fid}: {e}"
            )
            return
        try:
            bytes_written = file_open.write(data, offset)
            if bytes_written != len(data):
                replayer.logger.warning(
                    f"Write: Partial write for fid {original_fid} - "
                    f"requested {len(data)} bytes, wrote {bytes_written} bytes"
                )
            else:
                replayer.logger.debug(
                    f"Write: fid={original_fid}, offset={offset}, bytes_written={bytes_written}"
                )
        except SMBException as e:
            replayer.logger.error(f"Write failed for fid {original_fid}: {e}")
    else:
        replayer.logger.warning(f"Write: No mapping found for fid {original_fid}")
