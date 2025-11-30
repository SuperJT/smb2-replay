"""Common models shared across the API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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
