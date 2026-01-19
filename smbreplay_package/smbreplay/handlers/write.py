"""
SMB2 Write handler for modular replay system.
Writes zero-filled blocks since we don't extract TCP payload data.
"""

from smbprotocol.exceptions import SMBException


def handle_write(replayer, op):
    """Handle Write operation - writes zero-filled blocks.

    Since we don't extract write_data from TCP payloads (to save storage),
    we write zero-filled blocks to simulate the write operations and
    ensure files reach the correct size.

    If the requested write length exceeds the negotiated max write size,
    the write is split into multiple chunks.

    Args:
        replayer: SMB2Replayer instance
        op: Operation dictionary
    """
    original_fid = op.get("smb2.fid", "")

    # Get the file handle
    file_open = replayer.fid_mapping.get(original_fid)
    if not file_open:
        replayer.logger.warning(f"Write: FID {original_fid} not found in fid_mapping")
        return

    # Get offset and length
    offset = op.get("smb2.file_offset")
    length = op.get("smb2.write_length")

    if offset is None or length is None:
        replayer.logger.warning(
            f"Write: Missing offset or length for fid={original_fid}"
        )
        return

    try:
        # Convert to integers
        offset = int(offset)
        length = int(length)

        # Get max write size from the connection
        try:
            max_write_size = file_open.tree_connect.session.connection.max_write_size
        except AttributeError:
            # Fallback to a safe default if we can't get it
            max_write_size = 1048576  # 1MB default

        if length <= max_write_size:
            # Single write
            zero_data = bytes(length)
            file_open.write(zero_data, offset)
            replayer.logger.debug(
                f"Write: Wrote {length} zero bytes at offset {offset} "
                f"for fid={original_fid}"
            )
        else:
            # Split into multiple writes
            replayer.logger.debug(
                f"Write: Splitting large write ({length} bytes) into chunks "
                f"of max {max_write_size} bytes"
            )
            current_offset = offset
            remaining = length
            total_written = 0

            while remaining > 0:
                chunk_size = min(remaining, max_write_size)
                zero_data = bytes(chunk_size)
                file_open.write(zero_data, current_offset)
                total_written += chunk_size
                current_offset += chunk_size
                remaining -= chunk_size

            replayer.logger.debug(
                f"Write: Wrote {total_written} zero bytes in chunks "
                f"starting at offset {offset} for fid={original_fid}"
            )
    except (ValueError, SMBException) as e:
        replayer.logger.error(f"Write: Failed for fid={original_fid}: {e}")
