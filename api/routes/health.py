"""Health check endpoints."""

from fastapi import APIRouter, Depends

from api.models.common import HealthResponse, SystemInfo
from api.services.smbreplay_service import SMBReplayService, get_smbreplay_service

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health_check(
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> HealthResponse:
    """Check API health status.

    Returns basic health status including:
    - API status (ok, degraded, error)
    - API version
    - tshark availability
    """
    result = service.health_check()
    return HealthResponse(**result)


@router.get("/info", response_model=SystemInfo)
def get_system_info(
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> SystemInfo:
    """Get detailed system information.

    Returns comprehensive system status including:
    - tshark availability
    - Current capture path and validation status
    - Supported SMB2 commands
    - Traces folder location
    - Verbosity level
    - Packet count (if capture is loaded)
    """
    result = service.get_system_info()
    return SystemInfo(**result)
