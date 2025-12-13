"""Common models shared across the API."""

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# Path traversal prevention pattern
# Detects: "..", "/..", "../", and null bytes
# Note: Absolute paths (starting with /) are allowed - they're validated
# against TRACES_FOLDER at the service layer
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\.|/\.\.|\.\./)|\x00")


def validate_safe_path(value: Optional[str], field_name: str = "path") -> Optional[str]:
    """Validate that a path doesn't contain traversal sequences.

    Args:
        value: Path string to validate
        field_name: Name of field for error messages

    Returns:
        Original value if safe

    Raises:
        ValueError: If path contains traversal sequences
    """
    if value is None:
        return value

    if PATH_TRAVERSAL_PATTERN.search(value):
        raise ValueError(
            f"{field_name} contains invalid characters or path traversal sequences"
        )

    # Check for null bytes which can truncate paths
    if "\x00" in value:
        raise ValueError(f"{field_name} contains null bytes")

    return value


def validate_safe_identifier(value: Optional[str], field_name: str = "identifier") -> Optional[str]:
    """Validate that an identifier is safe (alphanumeric with limited special chars).

    Args:
        value: Identifier to validate
        field_name: Name of field for error messages

    Returns:
        Original value if safe

    Raises:
        ValueError: If identifier contains unsafe characters
    """
    if value is None:
        return value

    # Allow alphanumeric, underscore, hyphen, and dot (for file extensions)
    if not re.match(r"^[\w\-\.]+$", value):
        raise ValueError(
            f"{field_name} contains invalid characters (only alphanumeric, _, -, . allowed)"
        )

    # Prevent hidden files and traversal
    if value.startswith(".") or ".." in value:
        raise ValueError(f"{field_name} cannot start with '.' or contain '..'")

    return value


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    code: Optional[str] = Field(None, description="Error code for programmatic handling")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Health status", examples=["ok", "degraded", "error"])
    version: str = Field(..., description="API version")
    tshark_available: bool = Field(..., description="Whether tshark is available")


class SystemInfo(BaseModel):
    """System information response."""

    version: str = Field(..., description="API version")
    tshark_available: bool = Field(..., description="Whether tshark is available")
    capture_path: Optional[str] = Field(None, description="Current capture path")
    capture_valid: bool = Field(..., description="Whether capture path is valid")
    supported_commands: Dict[str, str] = Field(
        ..., description="Mapping of command codes to names"
    )
    traces_folder: str = Field(..., description="Path to traces folder")
    verbosity_level: int = Field(..., description="Current verbosity level")
    packet_count: Optional[int] = Field(None, description="Number of packets in capture")


class JobStatus(BaseModel):
    """Status of an async job."""

    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(
        ...,
        description="Job status",
        examples=["pending", "running", "completed", "failed"],
    )
    progress: Optional[int] = Field(
        None, description="Progress percentage (0-100)", ge=0, le=100
    )
    message: Optional[str] = Field(None, description="Status message")
    result: Optional[Dict[str, Any]] = Field(None, description="Job result when completed")
    error: Optional[str] = Field(None, description="Error message if failed")
