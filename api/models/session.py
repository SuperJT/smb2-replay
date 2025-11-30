"""Session-related models."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SessionSummary(BaseModel):
    """Summary information about a session."""

    session_id: str = Field(..., description="Session ID (hex format)")
    file_name: str = Field(..., description="Session file name")
    operation_count: Optional[int] = Field(
        None, description="Number of operations in session"
    )


class SessionListResponse(BaseModel):
    """Response for listing sessions."""

    sessions: List[SessionSummary] = Field(..., description="List of sessions")
    capture_path: Optional[str] = Field(None, description="Associated capture file path")
    total: int = Field(..., description="Total number of sessions")


class Operation(BaseModel):
    """An SMB2 operation from a session."""

    frame: str = Field(..., alias="Frame", description="Frame number")
    command: str = Field(..., alias="Command", description="SMB2 command name")
    path: Optional[str] = Field(None, alias="Path", description="File path")
    status: Optional[str] = Field(None, alias="Status", description="Operation status")
    status_desc: Optional[str] = Field(
        None, alias="StatusDesc", description="Status description"
    )
    tree: Optional[str] = Field(None, alias="Tree", description="SMB tree/share")

    # Allow additional fields from the raw operation data
    model_config = {"extra": "allow", "populate_by_name": True}


class SessionDetail(BaseModel):
    """Detailed session information."""

    session_id: str = Field(..., description="Session ID")
    file_name: str = Field(..., description="Session file name")
    operations: List[Operation] = Field(..., description="List of operations")
    operation_count: int = Field(..., description="Total operation count")
    file_filter: Optional[str] = Field(None, description="Applied file filter")
    fields: Optional[List[str]] = Field(None, description="Selected fields")


class OperationsRequest(BaseModel):
    """Request parameters for getting session operations."""

    file_filter: Optional[str] = Field(None, description="Filter by specific file path")
    fields: Optional[List[str]] = Field(None, description="Specific fields to include")
    capture_path: Optional[str] = Field(None, description="Override capture path")


class OperationsResponse(BaseModel):
    """Response containing session operations."""

    session_id: str = Field(..., description="Session ID")
    operations: List[Dict[str, Any]] = Field(..., description="Raw operation data")
    total: int = Field(..., description="Total number of operations")
    file_filter: Optional[str] = Field(None, description="Applied file filter")
