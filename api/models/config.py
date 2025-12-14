"""Configuration-related models."""

from pydantic import BaseModel, Field


class ConfigResponse(BaseModel):
    """Full configuration response."""

    traces_folder: str = Field(..., description="Path to traces folder")
    capture_path: str | None = Field(None, description="Current capture file path")
    verbosity_level: int = Field(..., description="Logging verbosity level (0-3)")
    session_id: str | None = Field(None, description="Current session ID")
    case_id: str | None = Field(None, description="Current case ID")
    trace_name: str | None = Field(None, description="Current trace file name")
    server_ip: str = Field(..., description="SMB server IP address")
    port: int = Field(..., description="SMB server port")
    domain: str = Field(..., description="SMB domain")
    username: str = Field(..., description="SMB username")
    password_set: bool = Field(
        ..., description="Whether a non-default password is configured"
    )
    tree_name: str = Field(..., description="SMB share/tree name")
    max_wait: float = Field(..., description="Maximum wait time for connections")


class ConfigUpdateRequest(BaseModel):
    """Request to update configuration."""

    traces_folder: str | None = Field(None, description="Path to traces folder")
    capture_path: str | None = Field(None, description="Path to capture file")
    verbosity_level: int | None = Field(
        None, description="Logging verbosity (0-3)", ge=0, le=3
    )
    session_id: str | None = Field(None, description="Session ID to use")
    case_id: str | None = Field(None, description="Case ID to use")
    trace_name: str | None = Field(None, description="Trace file name")
    server_ip: str | None = Field(None, description="SMB server IP address")
    port: int | None = Field(None, description="SMB server port", ge=1, le=65535)
    domain: str | None = Field(None, description="SMB domain")
    username: str | None = Field(None, description="SMB username")
    password: str | None = Field(None, description="SMB password")
    tree_name: str | None = Field(None, description="SMB share/tree name")
    max_wait: float | None = Field(
        None, description="Maximum wait time", ge=0.1, le=300.0
    )


class ConfigValueResponse(BaseModel):
    """Response for a single configuration value."""

    key: str = Field(..., description="Configuration key")
    value: str | None = Field(None, description="Configuration value")
