import logging
from smbprotocol.exceptions import SMBException

logger = logging.getLogger(__name__)

def handle_set_info(self, op):
    """Handle Set Info operation using smbprotocol."""
    original_fid = op.get('smb2.fid', '')
    file_open = self.fid_mapping.get(original_fid)

    if file_open:
        try:
            # Extract info_type, file_info_class, buffer, and additional_information from op
            info_type = int(op.get('smb2.setinfo.info_type', 0))
            file_info_class = int(op.get('smb2.setinfo.file_info_class', 0))
            additional_information = int(op.get('smb2.setinfo.additional_information', 0))
            buffer = op.get('smb2.setinfo.buffer', b'')
            if isinstance(buffer, str):
                buffer = bytes.fromhex(buffer)  # If buffer is hex string

            file_open.set_info(
                info_type=info_type,
                file_info_class=file_info_class,
                additional_information=additional_information,
                buffer=buffer
            )
            logger.info(
                f"Set Info: fid={original_fid}, info_type={info_type}, file_info_class={file_info_class}, "
                f"additional_information={additional_information}, buffer_len={len(buffer)}"
            )
        except SMBException as e:
            logger.error(f"Set Info failed for fid {original_fid}: {e}")
    else:
        logger.warning(f"Set Info: No mapping found for fid {original_fid}")