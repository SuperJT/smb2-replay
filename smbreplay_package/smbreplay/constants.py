"""
SMB2 Protocol Constants and Mappings.
Contains all SMB2 protocol constants, field mappings, and utility functions.
"""

import os
import pandas as pd
import subprocess
import uuid
from smbprotocol.header import NtStatus
from typing import Dict, List

# Configuration constants
SEP = 4 * " "
TSHARK_PATH = os.environ.get("TSHARK_PATH", "tshark")

# SMB2 Command Names
SMB2_OP_NAME_DESC = {
    0: ("Negotiate Protocol", ""),
    1: ("Session Setup", ""),
    2: ("Session Logoff", ""),
    3: ("Tree Connect", ""),
    4: ("Tree Disconnect", ""),
    5: ("Create", ""),
    6: ("Close", ""),
    7: ("Flush", ""),
    8: ("Read", ""),
    9: ("Write", ""),
    10: ("Lock", ""),
    11: ("IOCTL", ""),
    12: ("Cancel", ""),
    13: ("Echo", ""),
    14: ("Query Directory", ""),
    15: ("Change Notify", ""),
    16: ("Query Info", ""),
    17: ("Set Info", ""),
    18: ("Oplock Break", ""),
}

# FSCTL_* Constants
FSCTL_CONSTANTS = {
    "FSCTL_CREATE_OR_GET_OBJECT_ID": 0x900C0,
    "FSCTL_DELETE_OBJECT_ID": 0x900A0,
    "FSCTL_DELETE_REPARSE_POINT": 0x900AC,
    "FSCTL_DUPLICATE_EXTENTS_TO_FILE": 0x98344,
    "FSCTL_FILESYSTEM_GET_STATISTICS": 0x90060,
    "FSCTL_FIND_FILES_BY_SID": 0x9008F,
    "FSCTL_GET_COMPRESSION": 0x9003C,
    "FSCTL_GET_INTEGRITY_INFORMATION": 0x9027C,
    "FSCTL_GET_NTFS_VOLUME_DATA": 0x90064,
    "FSCTL_GET_REFS_VOLUME_DATA": 0x902D8,
    "FSCTL_GET_OBJECT_ID": 0x9009C,
    "FSCTL_GET_REPARSE_POINT": 0x900A8,
    "FSCTL_GET_RETRIEVAL_POINTERS": 0x90073,
    "FSCTL_IS_PATHNAME_VALID": 0x9002C,
    "FSCTL_LMR_SET_LINK_TRACKING_INFORMATION": 0x1400EC,
    "FSCTL_OFFLOAD_READ": 0x94264,
    "FSCTL_OFFLOAD_WRITE": 0x98268,
    "FSCTL_QUERY_ALLOCATED_RANGES": 0x940CF,
    "FSCTL_QUERY_FAT_BPB": 0x90058,
    "FSCTL_QUERY_FILE_REGIONS": 0x90284,
    "FSCTL_QUERY_ON_DISK_VOLUME_INFO": 0x9013C,
    "FSCTL_QUERY_SPARING_INFO": 0x90138,
    "FSCTL_READ_FILE_USN_DATA": 0x900EB,
    "FSCTL_RECALL_FILE": 0x90117,
    "FSCTL_SET_COMPRESSION": 0x9C040,
    "FSCTL_SET_DEFECT_MANAGEMENT": 0x98134,
    "FSCTL_SET_ENCRYPTION": 0x900D7,
    "FSCTL_SET_INTEGRITY_INFORMATION": 0x9C280,
    "FSCTL_SET_OBJECT_ID": 0x90098,
    "FSCTL_SET_OBJECT_ID_EXTENDED": 0x900BC,
    "FSCTL_SET_SPARSE": 0x900C4,
    "FSCTL_SET_ZERO_DATA": 0x980C8,
    "FSCTL_SET_ZERO_ON_DEALLOCATION": 0x90194,
    "FSCTL_SIS_COPYFILE": 0x90100,
    "FSCTL_WRITE_USN_CLOSE_RECORD": 0x900EF,
    "FSCTL_DFS_GET_REFERRALS": 0x60194,
    "FSCTL_PIPE_PEEK": 0x11400C,
    "FSCTL_PIPE_WAIT": 0x110018,
    "FSCTL_PIPE_TRANSCEIVE": 0x11C017,
    "FSCTL_SRV_COPYCHUNK": 0x1440F0,
    "FSCTL_SRV_ENUMERATE_SNAPSHOTS": 0x144064,
    "FSCTL_SRV_REQUEST_RESUME_KEY": 0x1400C4,
    "FSCTL_SRV_READ_HASH": 0x1440E8,
    "FSCTL_SRV_COPYCHUNK_WRITE": 0x1440F4,
    "FSCTL_LMR_REQUEST_RESILIENCY": 0x1400D8,
    "FSCTL_QUERY_NETWORK_INTERFACE_INFO": 0x1400FC,
    "FSCTL_SET_REPARSE_POINT": 0x900A4,
    "FSCTL_DFS_GET_REFERRALS_EX": 0x601A0,
    "FSCTL_FILE_LEVEL_TRIM": 0x98208,
    "FSCTL_VALIDATE_NEGOTIATE_INFO": 0x140204,
    "FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT": 0x90300,
    "FSCTL_SVHDX_SYNC_TUNNEL_REQUEST": 0x90304,
}

# File Information Classes
FILE_INFO_CLASSES = {
    "FILE_DIRECTORY_INFORMATION": 1,
    "FILE_FULL_DIRECTORY_INFORMATION": 2,
    "FILEID_FULL_DIRECTORY_INFORMATION": 38,
    "FILE_BOTH_DIRECTORY_INFORMATION": 3,
    "FILEID_BOTH_DIRECTORY_INFORMATION": 37,
    "FILENAMES_INFORMATION": 12,
}

# SMB2 Info Levels
SMB2_INFO_LEVELS = {
    "SMB2_0_INFO_FILE": 0x01,
    "SMB2_0_INFO_FILESYSTEM": 0x02,
    "SMB2_0_INFO_SECURITY": 0x03,
    "SMB2_0_INFO_QUOTA": 0x04,
}

# File Info Classes
SMB2_FILE_INFO_CLASSES = {
    "SMB2_FILE_ACCESS_INFO": 8,
    "SMB2_FILE_ALIGNMENT_INFO": 17,
    "SMB2_FILE_ALL_INFO": 18,
    "SMB2_FILE_ALTERNATE_NAME_INFO": 21,
    "SMB2_ATTRIBUTE_TAG_INFO": 35,
    "SMB2_FILE_BASIC_INFO": 4,
    "SMB2_FILE_COMPRESSION_INFO": 28,
    "SMB2_FILE_EA_INFO": 7,
    "SMB2_FULL_EA_INFO": 15,
    "SMB2_FILE_INTERNAL_INFO": 6,
    "SMB2_FILE_MODE_INFO": 16,
    "SMB2_FILE_NAME_INFO": 9,
    "SMB2_FILE_NETWORK_OPEN_INFO": 34,
    "SMB2_FILE_PIPE_INFO": 23,
    "SMB2_FILE_POSITION_INFO": 14,
    "SMB2_FILE_STANDARD_INFO": 5,
    "SMB2_FILE_STREAM_INFO": 22,
    "SMB2_FILESYSTEM_ATTRIBUTE_INFO": 5,
    "SMB2_FILESYSTEM_CONTROL_INFO": 6,
    "SMB2_FILESYSTEM_DEVICE_INFO": 4,
    "SMB2_FILESYSTEM_FULL_SIZE_INFO": 7,
    "SMB2_FILESYSTEM_OBJECT_ID_INFO": 8,
    "SMB2_FILESYSTEM_SECTOR_SIZE_INFO": 11,
    "SMB2_FILESYSTEM_SIZE_INFO": 3,
    "SMB2_FILESYSTEM_VOLUME_INFO": 1,
    "SMB2_FILESYSTEM_LABEL_INFO": 2,
    "SMB2_FILE_ALLOCATION_INFO": 19,
    "SMB2_FILE_DISPOSITION_INFO": 13,
    "SMB2_FILE_END_OF_FILE_INFO": 20,
    "SMB2_FILE_LINK_INFO": 11,
    "SMB2_FILE_RENAME_INFO": 10,
    "SMB2_FILE_SHORT_NAME_INFO": 45,
    "SMB2_FILE_VALID_DATA_LENGTH_INFO": 47,
}

# Query Directory Flags
SMB2_QUERY_DIRECTORY_FLAGS = {
    "SMB2_RESTART_SCANS": 0x01,
    "SMB2_RETURN_SINGLE_ENTRY": 0x02,
    "SMB2_INDEX_SPECIFIED": 0x04,
    "SMB2_REOPEN": 0x10,
}

# Create action mappings
CREATE_ACTION_DESC = {
    0: "FILE_SUPERSEDED",
    1: "FILE_OPENED",
    2: "FILE_CREATED",
    3: "FILE_OVERWRITTEN",
    4: "FILE_EXISTS",
    5: "FILE_DOES_NOT_EXIST",
}

# Tracking fields for network context
TRACKING_FIELDS = [
    "frame.number",
    "tcp.stream",
    "ip.src",
    "ip.dst",
    "frame.time",
    "frame.time_delta",
    "frame.len",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "ip.ttl",
    "ip.proto",
    "frame.time_epoch",
    "tcp.flags",
    "tcp.window_size",
    "ip.id",
]

# Hex fields requiring normalization
HEX_FIELDS = [
    "smb2.nt_status",
    "smb2.ioctl.function",
    "smb2.tid",
    "smb2.sesid",
    "smb2.msg_id",
    "smb2.fid",
    "smb2.create.action",
]


def check_tshark_availability() -> bool:
    """Verify local tshark is available and working."""
    try:
        result = subprocess.run(
            [TSHARK_PATH, "-v"], capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return False


def shorten_path(full_path: str, max_components: int = 3) -> str:
    """Shorten file paths to the last max_components."""
    if full_path == "Entire Stream":
        return full_path
    components = full_path.split("\\")
    if len(components) <= max_components:
        return full_path
    return "...\\" + "\\".join(components[-max_components:])


def normalize_path(path: str) -> str:
    """Normalize file paths for comparison."""
    if pd.isna(path) or path in ["N/A", "", "Entire Stream"]:
        return "N/A"
    return path.strip().replace("/", "\\").lower()


def get_tree_name_mapping(frames: pd.DataFrame) -> Dict[str, str]:
    """Map tree IDs to share names based on Tree Connect frames within a session."""
    tree_mapping = {}
    if isinstance(frames, list):
        frames = pd.DataFrame(frames)

    # Find Tree Connect request frames (cmd=3, not response)
    request_frames = frames[
        (frames["smb2.cmd"] == "3")
        & (frames["smb2.flags.response"].astype(str) != "True")
    ]

    for _, request_frame in request_frames.iterrows():
        tree_path = request_frame.get("smb2.tree", None)
        if pd.isna(tree_path) or not tree_path:
            continue
        share_name = tree_path.split("\\")[-1] if "\\" in tree_path else tree_path

        # Find corresponding response frames
        request_frame_num = int(request_frame.get("frame.number", 0))
        response_frames = frames[
            (frames["smb2.cmd"] == "3")
            & (frames["smb2.flags.response"].astype(str) == "True")
            & (frames["frame.number"].astype(int) > request_frame_num)
        ]

        for _, response_frame in response_frames.iterrows():
            tid = response_frame.get("smb2.tid", None)
            if tid and pd.notna(tid):
                # Normalize the tid to ensure consistent format
                tid_str = str(tid)
                tree_mapping[tid_str] = share_name
                break

    return tree_mapping


def normalize_hex_field(value, field_name):
    """Normalize hex fields to uppercase hex format."""
    if pd.isna(value) or value is None or value == "":
        return None
    try:
        if isinstance(value, str):
            # Handle multi-valued strings
            value = value.split(",")[0].strip().lower().replace("0x", "")
            value = int(value, 16)
        elif isinstance(value, (int, float)):
            value = int(value)
        else:
            return None

        if field_name in ["smb2.sesid", "smb2.msg_id"]:
            normalized = f"0x{value:016X}"  # 64-bit fields
        elif field_name == "smb2.create.action":
            normalized = str(value)  # Keep as integer string for mapping
        else:
            normalized = f"0x{value:08X}"  # 32-bit fields

        return normalized
    except (ValueError, TypeError):
        return None


def normalize_fid(value):
    """Normalize smb2.fid, handling UUID or hex formats."""
    if pd.isna(value) or value is None or value == "":
        return None
    try:
        if isinstance(value, str):
            # Handle UUID-like format
            if "-" in value:
                uuid_str = value.replace("-", "")
                uuid_obj = uuid.UUID(uuid_str)
                return f"0x{uuid_obj.int:032X}"
            # Handle multi-valued strings or hex
            value = value.split(",")[0].strip().lower().replace("0x", "")
            value = int(value, 16)
        elif isinstance(value, (int, float)):
            value = int(value)
        else:
            return None
        return f"0x{value:032X}"  # 128-bit field
    except (ValueError, TypeError):
        return None


def generate_smb2_fields(force_regenerate: bool = False) -> List[str]:
    """Generate SMB2 fields from tshark if needed."""
    smb2_fields_file = "smb2_fields.txt"

    if not os.path.exists(smb2_fields_file) or force_regenerate:
        if not check_tshark_availability():
            raise RuntimeError("Local tshark is not available")

        # Security: Use subprocess without shell=True to prevent command injection
        # Run tshark to get all fields
        tshark_result = subprocess.run(
            [TSHARK_PATH, "-G", "fields"],
            capture_output=True,
            text=True
        )
        if tshark_result.returncode != 0:
            raise RuntimeError(f"tshark -G fields failed: {tshark_result.stderr}")

        # Filter for smb2 fields in Python (instead of piping to grep)
        smb2_lines = [
            line for line in tshark_result.stdout.splitlines()
            if "smb2" in line.lower()
        ]

        # Write filtered results to file
        with open(smb2_fields_file, "w") as f:
            f.write("\n".join(smb2_lines))
            if smb2_lines:
                f.write("\n")

    with open(smb2_fields_file, "r") as f:
        smb2_field_lines = f.readlines()

    if not smb2_field_lines:
        raise RuntimeError(f"{smb2_fields_file} is empty")

    smb2_fields = []
    for line in smb2_field_lines:
        parts = line.strip().split("\t")
        if len(parts) >= 4 and parts[0] == "F" and parts[2].startswith("smb2."):
            smb2_fields.append(parts[2])

    return smb2_fields


def get_all_fields() -> List[str]:
    """Get all fields for ingestion."""
    smb2_fields = generate_smb2_fields()
    fields = sorted(set(TRACKING_FIELDS + smb2_fields))

    # Field corrections
    if "smb.file_name" in fields:
        fields[fields.index("smb.file_name")] = "smb2.filename"

    return fields


# Combine info level mappings
INFO_LEVEL_MAPPING = {
    **{str(k): v for k, v in FILE_INFO_CLASSES.items()},
    **{str(k): v for k, v in SMB2_INFO_LEVELS.items()},
    **{str(k): v for k, v in SMB2_FILE_INFO_CLASSES.items()},
}

# Field mappings for normalization and display
FIELD_MAPPINGS = {
    "smb2.cmd": {
        "mapping": {str(k): v[0] for k, v in SMB2_OP_NAME_DESC.items()},
        "normalize": lambda x: (
            str(
                int(
                    float(
                        x.split(",")[0]
                        .strip()
                        .replace("{", "")
                        .replace("}", "")
                        .replace("'", "")
                    )
                )
            )
            if x and pd.notna(x) and isinstance(x, str)
            else str(int(x)) if x and pd.notna(x) else None
        ),
        "description": "Maps SMB2 command codes to operation names.",
    },
    "smb2.nt_status": {
        "mapping": {
            f"0x{getattr(NtStatus, name):08X}": name
            for name in dir(NtStatus)
            if name.isupper() and isinstance(getattr(NtStatus, name), int)
        },
        "normalize": lambda x: normalize_hex_field(x, "smb2.nt_status"),
        "description": "Maps NT status codes to error names (smbprotocol).",
    },
    "smb2.ioctl.function": {
        "mapping": {str(f"0x{v:08X}"): k for k, v in FSCTL_CONSTANTS.items()},
        "normalize": lambda x: normalize_hex_field(x, "smb2.ioctl.function"),
        "description": "Maps IOCTL function codes to FSCTL names.",
    },
    "smb2.tid": {
        "mapping": {},
        "normalize": lambda x: normalize_hex_field(x, "smb2.tid"),
        "description": "Normalizes tree ID to hex format.",
    },
    "smb2.sesid": {
        "mapping": {},
        "normalize": lambda x: normalize_hex_field(x, "smb2.sesid"),
        "description": "Normalizes session ID to hex format.",
    },
    "smb2.msg_id": {
        "mapping": {},
        "normalize": lambda x: (
            str(
                int(
                    float(
                        x.split(",")[0]
                        .strip()
                        .replace("{", "")
                        .replace("}", "")
                        .replace("'", "")
                    )
                )
            )
            if x and pd.notna(x) and isinstance(x, str)
            else str(int(x)) if x and pd.notna(x) else None
        ),
        "description": "Keeps message ID as decimal string for comparison.",
    },
    "smb2.fid": {
        "mapping": {},
        "normalize": normalize_fid,
        "description": "Normalizes file ID to 128-bit hex format, handling UUIDs.",
    },
    "smb2.infolevel": {
        "mapping": INFO_LEVEL_MAPPING,
        "normalize": lambda x: str(int(x)) if x and pd.notna(x) else None,
        "description": "Maps info level codes to file, directory, and filesystem info class names.",
    },
    "smb2.create.action": {
        "mapping": {str(k): v for k, v in CREATE_ACTION_DESC.items()},
        "normalize": lambda x: normalize_hex_field(x, "smb2.create.action"),
        "description": "Maps create action codes to action names (e.g., FILE_OPENED).",
    },
}

# Critical fields that should be present
CRITICAL_FIELDS = [
    "smb2.cmd",
    "smb2.sesid",
    "smb2.filename",
    "smb2.write_data",
    "smb2.read_data",
    "smb2.ioctl.function",
    "smb2.tid",
    "smb2.nt_status",
    "smb2.msg_id",
    "smb2.fid",
    "smb2.tree",
    "smb2.create.disposition",
    "smb2.create.options",
    "smb2.share_flags",
    "smb2.access_mask",
    "smb2.file_attributes",
    "smb2.infolevel",
    "smb2.buffer_code",
    "smb2.create.action",
]
