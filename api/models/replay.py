"""Replay-related models."""

from typing import Any

from pydantic import BaseModel, Field


class ValidationCheck(BaseModel):
    """Result of a single validation check."""

    valid: bool = Field(..., description="Whether the check passed")
    total_operations: int | None = Field(None, description="Total operations checked")
    supported_operations: int | None = Field(
        None, description="Number of supported operations"
    )
    issues: list[str] = Field(default_factory=list, description="List of issues found")


class FileSystemCheck(BaseModel):
    """Result of file system validation check."""

    ready: bool = Field(..., description="Whether file system is ready")
    total_paths: int | None = Field(None, description="Total paths analyzed")
    accessible_paths: int | None = Field(None, description="Accessible paths count")
    missing_directories: list[str] = Field(
        default_factory=list, description="Missing directories"
    )
    created_files: int | None = Field(None, description="Files to be created")
    existing_files: int | None = Field(None, description="Existing files to open")
    warnings: list[str] = Field(default_factory=list, description="Warning messages")


class ValidationResult(BaseModel):
    """Result of replay validation."""

    ready: bool = Field(..., description="Whether replay is ready to proceed")
    checks: dict[str, Any] = Field(..., description="Individual check results")
    errors: list[str] = Field(default_factory=list, description="Error messages")
    warnings: list[str] = Field(default_factory=list, description="Warning messages")


class ValidateRequest(BaseModel):
    """Request for replay validation."""

    session_id: str = Field(..., description="Session ID to validate")
    capture_path: str | None = Field(None, description="Override capture path")
    file_filter: str | None = Field(None, description="Filter by file path")
    check_fs: bool = Field(True, description="Check file system structure")
    check_ops: bool = Field(True, description="Check operation validity")


class SetupRequest(BaseModel):
    """Request to setup file system infrastructure."""

    session_id: str = Field(..., description="Session ID to setup for")
    capture_path: str | None = Field(None, description="Override capture path")
    file_filter: str | None = Field(None, description="Filter by file path")
    dry_run: bool = Field(
        False, description="Show what would be created without changes"
    )
    force: bool = Field(False, description="Continue despite errors")

    # Optional server overrides
    server_ip: str | None = Field(None, description="Override server IP")
    domain: str | None = Field(None, description="Override domain")
    username: str | None = Field(None, description="Override username")
    password: str | None = Field(None, description="Override password")
    tree_name: str | None = Field(None, description="Override tree/share name")


class SetupResult(BaseModel):
    """Result of file system setup."""

    success: bool = Field(..., description="Whether setup was successful")
    directories_created: int = Field(0, description="Number of directories created")
    files_created: int = Field(0, description="Number of files created")
    errors: list[str] = Field(default_factory=list, description="Error messages")
    warnings: list[str] = Field(default_factory=list, description="Warning messages")
    dry_run: bool = Field(False, description="Whether this was a dry run")


class ReplayExecuteRequest(BaseModel):
    """Request to execute a replay."""

    session_id: str = Field(..., description="Session ID to replay")
    capture_path: str | None = Field(None, description="Override capture path")
    file_filter: str | None = Field(None, description="Filter by file path")

    # Optional server overrides
    server_ip: str | None = Field(None, description="Override server IP")
    domain: str | None = Field(None, description="Override domain")
    username: str | None = Field(None, description="Override username")
    password: str | None = Field(None, description="Override password")
    tree_name: str | None = Field(None, description="Override tree/share name")

    # Replay options
    validate_first: bool = Field(True, description="Validate before replaying")
    enable_ping: bool = Field(True, description="Ping server before starting")


class ReplayResult(BaseModel):
    """Result of a replay operation."""

    success: bool = Field(..., description="Whether replay was successful")
    total_operations: int = Field(0, description="Total operations attempted")
    successful_operations: int = Field(
        0, description="Operations completed successfully"
    )
    failed_operations: int = Field(0, description="Operations that failed")
    errors: list[str] = Field(default_factory=list, description="Error messages")
    validation: dict[str, Any] | None = Field(
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
    progress: int | None = Field(
        None, description="Progress percentage (0-100)", ge=0, le=100
    )
    message: str | None = Field(None, description="Status message")
    result: ReplayResult | None = Field(
        None, description="Replay result when completed"
    )
