"""Configuration endpoints."""

from fastapi import APIRouter, Depends, HTTPException

from api.models.config import ConfigResponse, ConfigUpdateRequest, ConfigValueResponse
from api.services.smbreplay_service import (
    SMBReplayService,
    SMBReplayServiceError,
    get_smbreplay_service,
)

router = APIRouter(prefix="/api/config", tags=["configuration"])


@router.get("", response_model=ConfigResponse)
def get_config(
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> ConfigResponse:
    """Get current configuration.

    Returns all configuration values including:
    - Traces folder and capture path
    - Session and case identifiers
    - SMB server connection settings
    - Verbosity level
    """
    result = service.get_config()
    return ConfigResponse(**result)


@router.put("", response_model=ConfigResponse)
def update_config(
    updates: ConfigUpdateRequest,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> ConfigResponse:
    """Update configuration values.

    Accepts partial updates - only provided fields will be changed.
    All configuration changes are persisted immediately.
    """
    result = service.update_config(updates.model_dump(exclude_unset=True))
    return ConfigResponse(**result)


@router.get("/{key}", response_model=ConfigValueResponse)
def get_config_value(
    key: str,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> ConfigValueResponse:
    """Get a specific configuration value.

    Args:
        key: Configuration key name. Valid keys include:
            - traces_folder, capture_path, verbosity_level
            - session_id, case_id, trace_name
            - server_ip, port, domain, username, tree_name, max_wait
    """
    try:
        value = service.get_config_value(key)
        return ConfigValueResponse(key=key, value=value)
    except SMBReplayServiceError as e:
        raise HTTPException(status_code=400, detail=e.message)
