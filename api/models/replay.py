"""Replay-related models."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ValidationCheck(BaseModel):
    """Result of a single validation check."""

    valid: bool = Field(..., description="Whether the check passed")
    total_operations: Optional[int] = Field(None, description="Total operations checked")
    supported_operations: Optional[int] = Field(
        None, description="Number of supported operations"
    )
    issues: List[str] = Field(default_factory=list, description="List of issues found")


class FileSystemCheck(BaseModel):
    """Result of file system validation check."""

    ready: bool = Field(..., description="Whether file system is ready")
    total_paths: Optional[int] = Field(None, description="Total paths analyzed")
    accessible_paths: Optional[int] = Field(None, description="Accessible paths count")
    missing_directories: List[str] = Field(
        default_factory=list, description="Missing directories"
    )
    created_files: Optional[int] = Field(None, description="Files to be created")
    existing_files: Optional[int] = Field(None, description="Existing files to open")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")


class ValidationResult(BaseModel):
    """Result of replay validation."""

    ready: bool = Field(..., description="Whether replay is ready to proceed")
    checks: Dict[str, Any] = Field(..., description="Individual check results")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")


class ValidateRequest(BaseModel):
    """Request for replay validation."""

    session_id: str = Field(..., description="Session ID to validate")
    capture_path: Optional[str] = Field(None, description="Override capture path")
    file_filter: Optional[str] = Field(None, description="Filter by file path")
    check_fs: bool = Field(True, description="Check file system structure")
    check_ops: bool = Field(True, description="Check operation validity")


class SetupRequest(BaseModel):
    """Request to setup file system infrastructure."""

    session_id: str = Field(..., description="Session ID to setup for")
    capture_path: Optional[str] = Field(None, description="Override capture path")
    file_filter: Optional[str] = Field(None, description="Filter by file path")
    dry_run: bool = Field(
        False, description="Show what would be created without changes"
    )
    force: bool = Field(False, description="Continue despite errors")

    # Optional server overrides
    server_ip: Optional[str] = Field(None, description="Override server IP")
    username: Optional[str] = Field(None, description="Override username")
    password: Optional[str] = Field(None, description="Override password")
    tree_name: Optional[str] = Field(None, description="Override tree/share name")


class SetupResult(BaseModel):
    """Result of file system setup."""

    success: bool = Field(..., description="Whether setup was successful")
    directories_created: int = Field(0, description="Number of directories created")
    files_created: int = Field(0, description="Number of files created")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    warnings: List[str] = Field(default_factory=list, description="Warning messages")
    dry_run: bool = Field(False, description="Whether this was a dry run")


class ReplayExecuteRequest(BaseModel):
    """Request to execute a replay."""

    session_id: str = Field(..., description="Session ID to replay")
    capture_path: Optional[str] = Field(None, description="Override capture path")
    file_filter: Optional[str] = Field(None, description="Filter by file path")

    # Optional server overrides
    server_ip: Optional[str] = Field(None, description="Override server IP")
    domain: Optional[str] = Field(None, description="Override domain")
    username: Optional[str] = Field(None, description="Override username")
    password: Optional[str] = Field(None, description="Override password")
    tree_name: Optional[str] = Field(None, description="Override tree/share name")

    # Replay options
    validate_first: bool = Field(True, description="Validate before replaying")
    enable_ping: bool = Field(True, description="Ping server before starting")


class ReplayResult(BaseModel):
    """Result of a replay operation."""

    success: bool = Field(..., description="Whether replay was successful")
    total_operations: int = Field(0, description="Total operations attempted")
    successful_operations: int = Field(0, description="Operations completed successfully")
    failed_operations: int = Field(0, description="Operations that failed")
    errors: List[str] = Field(default_factory=list, description="Error messages")
    validation: Optional[Dict[str, Any]] = Field(
        None, description="Validation results if validation failed"
    )


class ReplayStatusResponse(BaseModel):
    """Status of a replay job."""

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
    result: Optional[ReplayResult] = Field(
        None, description="Replay result when completed"
    )
