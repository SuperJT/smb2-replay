"""Trace/PCAP-related models."""

from typing import List, Optional

from pydantic import BaseModel, Field


class TraceFile(BaseModel):
    """Information about a trace file."""

    path: str = Field(..., description="Relative path to trace file from case folder")
    name: str = Field(..., description="File name")
    case_id: Optional[str] = Field(None, description="Associated case ID")


class TraceListResponse(BaseModel):
    """Response for listing trace files."""

    traces: List[TraceFile] = Field(..., description="List of trace files")
    case_id: Optional[str] = Field(None, description="Case ID used for listing")
    total: int = Field(..., description="Total number of traces found")


class IngestRequest(BaseModel):
    """Request to ingest a PCAP file."""

    path: str = Field(..., description="Path to PCAP file (absolute or relative to case)")
    force: bool = Field(False, description="Force re-ingestion even if data exists")
    reassembly: bool = Field(False, description="Enable TCP reassembly during parsing")
    case_id: Optional[str] = Field(
        None, description="Case ID (required for relative paths)"
    )


class IngestResult(BaseModel):
    """Result of PCAP ingestion."""

    success: bool = Field(..., description="Whether ingestion was successful")
    sessions: List[str] = Field(
        default_factory=list, description="List of session file names"
    )
    session_count: int = Field(0, description="Number of sessions extracted")
    total_frames: Optional[int] = Field(None, description="Total frames processed")
    processing_time: Optional[float] = Field(
        None, description="Processing time in seconds"
    )
    error: Optional[str] = Field(None, description="Error message if failed")


class IngestStatusResponse(BaseModel):
    """Status of an ingestion job."""

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
    result: Optional[IngestResult] = Field(
        None, description="Ingestion result when completed"
    )
