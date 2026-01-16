"""
SMB2 Write handler for modular replay system.
Sets file size via SETINFO instead of writing actual data.
This avoids extracting/storing large amounts of TCP data while achieving the same file system state.
"""

import struct

from smbprotocol.exceptions import SMBException


def handle_write(replayer, op):
    """Handle Write operation by setting file EOF via SETINFO.
    
    Instead of writing actual data (which requires extracting and storing TCP payloads),
    we calculate the end-of-file position and use SETINFO to set it.
    This creates sparse files with correct sizes.
    
    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)
    if file_open:
        # Calculate end-of-file from write offset + length
        offset = int(op.get("smb2.file_offset", 0))
        length = int(op.get("smb2.write_length", 0))
        
        if length == 0:
            replayer.logger.debug(
                f"Write: Zero-length write for fid {original_fid}, skipping"
            )
            return
        
        end_of_file = offset + length
        
        try:
            # Use SETINFO to set end-of-file (creates sparse file)
            # info_type=1 (FILE), file_info_class=20 (END_OF_FILE_INFO)
            eof_buffer = struct.pack('<Q', end_of_file)  # 8-byte little-endian
            file_open.set_info(
                info_type=1,
                file_info_class=20,  # SMB2_FILE_END_OF_FILE_INFO
                additional_information=0,
                buffer=eof_buffer,
            )
            replayer.logger.debug(
                f"Write: Set EOF for fid={original_fid}, offset={offset}, length={length}, eof={end_of_file}"
            )
        except SMBException as e:
            replayer.logger.error(
                f"Write: Failed to set EOF for fid {original_fid}: {e}"
            )
    else:
        replayer.logger.warning(f"Write: No mapping found for fid {original_fid}")
