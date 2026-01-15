"""Session-related models."""

from typing import Any

import numpy as np
from pydantic import BaseModel, Field, field_validator

from .common import validate_safe_path


def _sanitize_numpy(value: Any) -> Any:
    """Recursively convert numpy types to Python native types for JSON serialization."""
    if isinstance(value, np.ndarray):
        return value.tolist()
    elif isinstance(value, (np.integer, np.floating)):
        return value.item()
    elif isinstance(value, np.bool_):
        return bool(value)
    elif isinstance(value, dict):
        return {k: _sanitize_numpy(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_sanitize_numpy(v) for v in value]
    return value


class SessionSummary(BaseModel):
    """Summary information about a session."""

    session_id: str = Field(..., description="Session ID (hex format)")
    file_name: str = Field(..., description="Session file name")
    operation_count: int | None = Field(
        None, description="Number of operations in session"
    )


class SessionListResponse(BaseModel):
    """Response for listing sessions."""

    sessions: list[SessionSummary] = Field(..., description="List of sessions")
    capture_path: str | None = Field(None, description="Associated capture file path")
    total: int = Field(..., description="Total number of sessions")


class Operation(BaseModel):
    """An SMB2 operation from a session."""

    frame: str = Field(..., alias="Frame", description="Frame number")
    command: str = Field(..., alias="Command", description="SMB2 command name")
    path: str | None = Field(None, alias="Path", description="File path")
    status: str | None = Field(None, alias="Status", description="Operation status")
    status_desc: str | None = Field(
        None, alias="StatusDesc", description="Status description"
    )
    tree: str | None = Field(None, alias="Tree", description="SMB tree/share")

    # Allow additional fields from the raw operation data
    model_config = {"extra": "allow", "populate_by_name": True}


class SessionDetail(BaseModel):
    """Detailed session information."""

    session_id: str = Field(..., description="Session ID")
    file_name: str = Field(..., description="Session file name")
    operations: list[Operation] = Field(..., description="List of operations")
    operation_count: int = Field(..., description="Total operation count")
    file_filter: str | None = Field(None, description="Applied file filter")
    fields: list[str] | None = Field(None, description="Selected fields")


class OperationsRequest(BaseModel):
    """Request parameters for getting session operations."""

    file_filter: str | None = Field(None, description="Filter by specific file path")
    fields: list[str] | None = Field(None, description="Specific fields to include")
    capture_path: str | None = Field(None, description="Override capture path")

    @field_validator("file_filter")
    @classmethod
    def validate_file_filter(cls, v):
        """Validate file_filter doesn't contain path traversal."""
        return validate_safe_path(v, "file_filter")

    @field_validator("capture_path")
    @classmethod
    def validate_capture_path(cls, v):
        """Validate capture_path doesn't contain path traversal."""
        return validate_safe_path(v, "capture_path")


class OperationsResponse(BaseModel):
    """Response containing session operations."""

    session_id: str = Field(..., description="Session ID")
    operations: list[dict[str, Any]] = Field(..., description="Raw operation data")
    total: int = Field(..., description="Total number of operations")
    file_filter: str | None = Field(None, description="Applied file filter")

    @field_validator("operations", mode="before")
    @classmethod
    def sanitize_operations(cls, v):
        """Convert numpy types to Python native types for JSON serialization."""
        if isinstance(v, list):
            return [_sanitize_numpy(op) for op in v]
        return v
