import math

import logging
from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open
from typing import Any, Dict, List, Optional

from smbreplay.utils import get_share_relative_path

logger = logging.getLogger(__name__)


def handle_create(
    self,
    tree,
    op: Dict[str, Any],
    all_operations: Optional[List[Dict[str, Any]]] = None,
):
    """Handle Create operation using smbprotocol.

    Args:
        tree: TreeConnect object for the share
        op: Operation dictionary
        all_operations: All operations in the session (for determining create type and open/create)
    """
    filename = op.get("smb2.filename", "")
    # Ensure filename is a string and not nan/float

    if isinstance(filename, float):
        if math.isnan(filename):
            logger.error(f"Create operation skipped: filename is NaN for op: {op}")
            self.state["last_new_fid"] = None
            return
        filename = str(filename)
    elif not isinstance(filename, str):
        filename = str(filename)
    # Defensive: skip if filename is empty or 'nan' string
    if not filename or filename.lower() == "nan":
        logger.error(
            f"Create operation skipped: invalid filename '{filename}' for op: {op}"
        )
        self.state["last_new_fid"] = None
        return
    rel_filename = get_share_relative_path(self, filename)
    create_type, open_action = ("file", "create")
    if all_operations:
        create_type, open_action = self.determine_create_type_and_action(
            op, all_operations
        )

    # Read all create parameters from the operation data
    impersonation_level = int(
        op.get("smb2.impersonation_level", 0)
    )  # Default SECURITY_ANONYMOUS
    desired_access = int(
        op.get("smb2.desired_access", 0x80000000 | 0x40000000)
    )  # Default GENERIC_READ | GENERIC_WRITE
    file_attributes = int(
        op.get("smb2.file_attributes", 0)
    )  # Default FILE_ATTRIBUTE_NORMAL
    share_access = int(
        op.get("smb2.share_access", 0x00000001)
    )  # Default FILE_SHARE_READ
    create_disposition = int(
        op.get("smb2.create_disposition", 2)
    )  # Default FILE_CREATE
    create_options = int(op.get("smb2.create_options", 0))  # Default no special options

    # Adjust parameters based on create type
    if create_type == "directory":
        file_attributes = 0x00000010  # FILE_ATTRIBUTE_DIRECTORY
        create_options = 1  # FILE_DIRECTORY_FILE
        desired_access = 0x80000000  # GENERIC_READ for directories
        logger.debug(f"Creating directory: {rel_filename} ({open_action})")
    else:
        logger.debug(f"Creating file: {rel_filename} ({open_action})")

    # Adjust create_disposition based on open_action if not explicitly set
    # FILE_CREATE = 2, FILE_OPEN = 1, FILE_OPEN_IF = 3
    if open_action == "open" and create_disposition == 2:
        # If the trace says open but disposition is FILE_CREATE, override to FILE_OPEN_IF
        create_disposition = 3
    elif open_action == "create" and create_disposition == 1:
        # If the trace says create but disposition is FILE_OPEN, override to FILE_CREATE
        create_disposition = 2

    logger.info(f"Create operation parameters for {rel_filename}:")
    logger.info(f"  Type: {create_type}")
    logger.info(f"  Action: {open_action}")
    logger.info(f"  impersonation_level: {impersonation_level}")
    logger.info(f"  desired_access: {desired_access}")
    logger.info(f"  file_attributes: {file_attributes}")
    logger.info(f"  share_access: {share_access}")
    logger.info(f"  create_disposition: {create_disposition}")
    logger.info(f"  create_options: {create_options}")

    try:
        file_open = Open(tree, rel_filename)
        # Create with parameters from the operation data
        file_open.create(
            impersonation_level=impersonation_level,
            desired_access=desired_access,
            file_attributes=file_attributes,
            share_access=share_access,
            create_disposition=create_disposition,
            create_options=create_options,
        )
        self.state["last_new_fid"] = file_open
        logger.info(f"Create: {rel_filename}, Open object={file_open}")
        # Validate response - successful create should return STATUS_SUCCESS (0x00000000)
        self.validate_response(op, "0x00000000")
    except SMBException as e:
        logger.error(f"Create failed for {rel_filename}: {e}")
        self.state["last_new_fid"] = None
        # Extract NT status from error message
        actual_status = "0x00000000"
        if "STATUS_" in str(e):
            # Try to extract status code from error message
            error_str = str(e)
            if "0x" in error_str:
                import re

                hex_match = re.search(r"0x[0-9a-fA-F]{8}", error_str)
                if hex_match:
                    actual_status = hex_match.group(0)
        # Validate response against expected status
        self.validate_response(op, actual_status, str(e))
