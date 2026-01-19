"""
SMB2 Read handler for modular replay system.
Reads data from the mapped Open object for the given FID using smbprotocol.
"""

from smbprotocol.exceptions import SMBException


def handle_read(replayer, op):
    """Handle Read operation using smbprotocol Open object.

    If the requested read length exceeds the negotiated max read size,
    the read is split into multiple chunks.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    original_fid = op.get("smb2.fid", "")
    file_open = replayer.fid_mapping.get(original_fid)
    if file_open:
        offset = int(op.get("smb2.file_offset", 0))
        length = int(op.get("smb2.read_length", 1024))

        # Get max read size from the connection
        # The Open object has a tree_connect -> session -> connection chain
        try:
            max_read_size = file_open.tree_connect.session.connection.max_read_size
        except AttributeError:
            # Fallback to a safe default if we can't get it
            max_read_size = 1048576  # 1MB default

        try:
            if length <= max_read_size:
                # Single read
                data = file_open.read(length, offset)
                replayer.logger.debug(
                    f"Read: fid={original_fid}, offset={offset}, length={length}, "
                    f"data_length={len(data) if data else 0}"
                )
            else:
                # Split into multiple reads
                total_read = 0
                current_offset = offset
                remaining = length
                chunks = []

                replayer.logger.debug(
                    f"Read: Splitting large read ({length} bytes) into chunks "
                    f"of max {max_read_size} bytes"
                )

                while remaining > 0:
                    chunk_size = min(remaining, max_read_size)
                    chunk_data = file_open.read(chunk_size, current_offset)
                    if chunk_data:
                        chunks.append(chunk_data)
                        actual_read = len(chunk_data)
                        total_read += actual_read
                        current_offset += actual_read
                        remaining -= actual_read
                        # If we got less than requested, we've hit EOF
                        if actual_read < chunk_size:
                            break
                    else:
                        # No data returned, EOF
                        break

                data = b"".join(chunks) if chunks else b""
                replayer.logger.debug(
                    f"Read: fid={original_fid}, offset={offset}, "
                    f"requested={length}, total_read={total_read}"
                )
        except SMBException as e:
            replayer.logger.error(f"Read failed for fid {original_fid}: {e}")
    else:
        replayer.logger.warning(f"Read: No mapping found for fid {original_fid}")
