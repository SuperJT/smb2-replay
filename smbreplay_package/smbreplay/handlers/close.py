"""
SMB2 Close handler for modular replay system.
Closes the mapped Open object for the given FID using smbprotocol.
"""

from smbprotocol.exceptions import SMBException


def handle_close(replayer, op):
    """Handle Close operation using smbprotocol Open object.
    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)
    if file_open:
        try:
            file_open.close()
            replayer.logger.info(f"Closed file for fid {original_fid}")
        except SMBException as e:
            replayer.logger.error(f"Close failed for fid {original_fid}: {e}")
    else:
        replayer.logger.warning(f"Close: No mapping found for fid {original_fid}")
