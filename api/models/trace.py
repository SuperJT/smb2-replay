"""Trace/PCAP-related models."""

from pydantic import BaseModel, Field, field_validator

from .common import validate_safe_identifier, validate_safe_path


class TraceFile(BaseModel):
    """Information about a trace file."""

    path: str = Field(..., description="Relative path to trace file from case folder")
    name: str = Field(..., description="File name")
    case_id: str | None = Field(None, description="Associated case ID")


class TraceListResponse(BaseModel):
    """Response for listing trace files."""

    traces: list[TraceFile] = Field(..., description="List of trace files")
    case_id: str | None = Field(None, description="Case ID used for listing")
    total: int = Field(..., description="Total number of traces found")


class IngestRequest(BaseModel):
    """Request to ingest a PCAP file."""

    path: str = Field(
        ...,
        description="Path to PCAP file (absolute or relative to case)",
        alias="capture_path",  # Accept capture_path from frontend
    )
    force: bool = Field(False, description="Force re-ingestion even if data exists")
    reassembly: bool = Field(False, description="Enable TCP reassembly during parsing")
    case_id: str | None = Field(
        None, description="Case ID (required for relative paths)", alias="caseId"
    )

    # Accept both snake_case (Python) and camelCase/aliases (frontend)
    model_config = {"populate_by_name": True}

    @field_validator("path")
    @classmethod
    def validate_path(cls, v):
        """Validate path doesn't contain traversal sequences."""
        return validate_safe_path(v, "path")

    @field_validator("case_id")
    @classmethod
    def validate_case_id(cls, v):
        """Validate case_id is a safe identifier."""
        return validate_safe_identifier(v, "case_id")


class IngestResult(BaseModel):
    """Result of PCAP ingestion."""

    success: bool = Field(..., description="Whether ingestion was successful")
    sessions: list[str] = Field(
        default_factory=list, description="List of session file names"
    )
    session_count: int = Field(default=0, description="Number of sessions extracted")
    total_frames: int | None = Field(
        default=None, description="Total frames processed"
    )
    processing_time: float | None = Field(
        default=None, description="Processing time in seconds"
    )
    error: str | None = Field(default=None, description="Error message if failed")


class IngestStatusResponse(BaseModel):
    """Status of an ingestion job."""

    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(
        ...,
        description="Job status",
        examples=["pending", "running", "completed", "failed"],
    )
    progress: int | None = Field(
        None, description="Progress percentage (0-100)", ge=0, le=100
    )
    message: str | None = Field(None, description="Status message")
    result: IngestResult | None = Field(
        None, description="Ingestion result when completed"
    )
