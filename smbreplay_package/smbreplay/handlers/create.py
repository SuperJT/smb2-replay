import logging
import math
import uuid
from typing import Any

from smbprotocol.create_contexts import (
    LeaseState,
    SMB2CreateContextRequest,
    SMB2CreateRequestLease,
)
from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open, RequestedOplockLevel

from smbreplay.utils import get_share_relative_path

logger = logging.getLogger(__name__)


def _find_response_for_request(
    op: dict[str, Any], all_operations: list[dict[str, Any]] | None
) -> dict[str, Any] | None:
    """Find the response frame matching a request by message ID.

    Args:
        op: The request operation dictionary
        all_operations: All operations in the session

    Returns:
        The matching response operation, or None if not found
    """
    if not all_operations:
        return None

    msg_id = op.get("smb2.msg_id")
    if msg_id is None:
        return None

    # Handle array-wrapped values
    if isinstance(msg_id, (list, tuple)):
        msg_id = msg_id[0] if msg_id else None
    msg_id = str(msg_id) if msg_id is not None else None

    for resp_op in all_operations:
        resp_flags = resp_op.get("smb2.flags.response")
        if isinstance(resp_flags, (list, tuple)):
            resp_flags = resp_flags[0] if resp_flags else None
        resp_msg_id = resp_op.get("smb2.msg_id")
        if isinstance(resp_msg_id, (list, tuple)):
            resp_msg_id = resp_msg_id[0] if resp_msg_id else None

        if str(resp_flags) == "True" and str(resp_msg_id) == msg_id:
            return resp_op

    return None


def _get_granted_oplock_and_lease(
    response: dict[str, Any] | None,
) -> tuple[int, int | None, str | None]:
    """Extract the granted oplock level and lease state from a CREATE response.

    Args:
        response: The CREATE response operation dictionary

    Returns:
        Tuple of (oplock_level, lease_state, lease_key) where:
        - oplock_level: 0x00 (NONE), 0x01 (II), 0x08 (EXCLUSIVE), 0x09 (BATCH), 0xff (LEASE)
        - lease_state: SMB2_LEASE_* flags if oplock_level is 0xff, else None
        - lease_key: Lease key GUID string if oplock_level is 0xff, else None
    """
    if response is None:
        # No response found, request no oplock
        return RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE, None, None

    # Extract oplock level from response
    oplock = response.get("smb2.create.oplock")
    if isinstance(oplock, (list, tuple)):
        oplock = oplock[0] if oplock else None

    if oplock is None or str(oplock) in ("", "nan", "N/A"):
        return RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE, None, None

    # Parse oplock value
    try:
        if isinstance(oplock, str):
            oplock = oplock.strip()
            if oplock.startswith("0x") or oplock.startswith("0X"):
                oplock_level = int(oplock, 16)
            else:
                oplock_level = int(oplock)
        else:
            oplock_level = int(oplock)
    except (ValueError, TypeError):
        logger.warning(f"Could not parse oplock value '{oplock}', using NONE")
        return RequestedOplockLevel.SMB2_OPLOCK_LEVEL_NONE, None, None

    # If oplock is 0xff (LEASE), extract lease state and key
    if oplock_level == RequestedOplockLevel.SMB2_OPLOCK_LEVEL_LEASE:
        lease_state = response.get("smb2.lease.lease_state")
        lease_key = response.get("smb2.lease.lease_key")

        if isinstance(lease_state, (list, tuple)):
            lease_state = lease_state[0] if lease_state else None
        if isinstance(lease_key, (list, tuple)):
            lease_key = lease_key[0] if lease_key else None

        # Parse lease state
        lease_state_int = None
        if lease_state is not None and str(lease_state) not in ("", "nan", "N/A"):
            try:
                if isinstance(lease_state, str):
                    lease_state = lease_state.strip()
                    if lease_state.startswith("0x") or lease_state.startswith("0X"):
                        lease_state_int = int(lease_state, 16)
                    else:
                        lease_state_int = int(lease_state)
                else:
                    lease_state_int = int(lease_state)
            except (ValueError, TypeError):
                logger.warning(f"Could not parse lease_state '{lease_state}'")
                lease_state_int = LeaseState.SMB2_LEASE_NONE

        return oplock_level, lease_state_int, str(lease_key) if lease_key else None

    return oplock_level, None, None


def _safe_int(value: Any, default: int, field_name: str = "field") -> int:
    """Safely convert a value to int with error handling.

    Args:
        value: Value to convert (may be str, int, float, hex string, or None)
        default: Default value if conversion fails
        field_name: Name of the field for logging

    Returns:
        Integer value or default
    """
    if value is None:
        return default
    try:
        # Handle hex strings like "0x80000000"
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("0x") or value.startswith("0X"):
                return int(value, 16)
            elif value.startswith("-0x") or value.startswith("-0X"):
                return -int(value[1:], 16)
        return int(value)
    except (ValueError, TypeError) as e:
        logger.warning(
            f"Invalid {field_name} value '{value}': {e}, using default {default}"
        )
        return default


def handle_create(
    self,
    tree,
    op: dict[str, Any],
    all_operations: list[dict[str, Any]] | None = None,
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

    # Read all create parameters from the operation data with safe conversion
    impersonation_level = _safe_int(
        op.get("smb2.impersonation_level"), 0, "impersonation_level"
    )  # Default SECURITY_ANONYMOUS
    desired_access = _safe_int(
        op.get("smb2.desired_access"), 0x80000000 | 0x40000000, "desired_access"
    )  # Default GENERIC_READ | GENERIC_WRITE
    file_attributes = _safe_int(
        op.get("smb2.file_attributes"), 0, "file_attributes"
    )  # Default FILE_ATTRIBUTE_NORMAL
    share_access = _safe_int(
        op.get("smb2.share_access"), 0x00000001, "share_access"
    )  # Default FILE_SHARE_READ
    create_disposition = _safe_int(
        op.get("smb2.create_disposition"), 2, "create_disposition"
    )  # Default FILE_CREATE
    create_options = _safe_int(
        op.get("smb2.create_options"), 0, "create_options"
    )  # Default no special options

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

    # Get the granted oplock/lease from the response to request the same level
    response = _find_response_for_request(op, all_operations)
    oplock_level, lease_state, lease_key = _get_granted_oplock_and_lease(response)

    # Build create_contexts for lease if needed
    create_contexts: list[Any] = []
    if oplock_level == RequestedOplockLevel.SMB2_OPLOCK_LEVEL_LEASE and lease_state is not None:
        # Create a lease request context with the granted lease state
        lease_request = SMB2CreateRequestLease()
        # Use the original lease key if available, otherwise generate a new one
        if lease_key:
            try:
                lease_request["lease_key"] = uuid.UUID(lease_key).bytes_le
            except (ValueError, AttributeError):
                lease_request["lease_key"] = uuid.uuid4().bytes_le
        else:
            lease_request["lease_key"] = uuid.uuid4().bytes_le
        lease_request["lease_state"] = lease_state
        lease_request["lease_flags"] = 0
        lease_request["lease_duration"] = 0

        # Wrap in create context
        lease_context = SMB2CreateContextRequest()
        lease_context["buffer_name"] = b"RqLs"  # SMB2_CREATE_REQUEST_LEASE
        lease_context["buffer_data"] = lease_request

        create_contexts.append(lease_context)
        logger.info(f"  oplock_level: LEASE (0xff)")
        logger.info(f"  lease_state: {hex(lease_state)} (R={bool(lease_state & 1)}, H={bool(lease_state & 2)}, W={bool(lease_state & 4)})")
        logger.info(f"  lease_key: {lease_key}")
    else:
        logger.info(f"  oplock_level: {hex(oplock_level)}")

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
            oplock_level=oplock_level,
            create_contexts=create_contexts if create_contexts else None,
        )
        self.state["last_new_fid"] = file_open
        logger.info(f"Create: {rel_filename}, Open object={file_open}")
        # Validate response - successful create should return STATUS_SUCCESS (0x00000000)
        self.validate_response(op, "0x00000000")
    except SMBException as e:
        logger.error(f"Create failed for {rel_filename}: {e}")
        self.state["last_new_fid"] = None
        # Extract NT status from error message
        # Default to STATUS_UNSUCCESSFUL (0xC0000001) - never claim success on exception
        actual_status = "0xC0000001"
        error_str = str(e)
        if "0x" in error_str:
            import re

            hex_match = re.search(r"0x[0-9a-fA-F]{8}", error_str)
            if hex_match:
                actual_status = hex_match.group(0)
        # Validate response against expected status
        self.validate_response(op, actual_status, error_str)
