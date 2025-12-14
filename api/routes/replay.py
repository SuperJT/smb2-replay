"""Replay operation endpoints."""

from fastapi import APIRouter, Depends, HTTPException

from api.models.replay import (
    ReplayExecuteRequest,
    ReplayResult,
    SetupRequest,
    SetupResult,
    ValidateRequest,
    ValidationResult,
)
from api.services.smbreplay_service import (
    SMBReplayService,
    SMBReplayServiceError,
    get_smbreplay_service,
)

router = APIRouter(prefix="/api/replay", tags=["replay"])


@router.post("/validate", response_model=ValidationResult)
def validate_replay(
    request: ValidateRequest,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> ValidationResult:
    """Validate replay readiness.

    Checks whether the specified session can be replayed successfully.

    Validation includes:
    - Operation validity (supported commands, required fields)
    - File system structure (directories that need to be created)

    Args:
        request: Validation parameters including session_id and check options.
    """
    try:
        result = service.validate_replay(
            session_id=request.session_id,
            capture_path=request.capture_path,
            file_filter=request.file_filter,
            check_fs=request.check_fs,
            check_ops=request.check_ops,
        )
        return ValidationResult(**result)
    except SMBReplayServiceError as e:
        if e.code == "SESSION_NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.message) from e
        raise HTTPException(status_code=400, detail=e.message) from e


@router.post("/setup", response_model=SetupResult)
def setup_infrastructure(
    request: SetupRequest,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> SetupResult:
    """Setup file system infrastructure for replay.

    Connects to the SMB server and creates the directory structure
    and files needed for replay. Also cleans up existing files to
    ensure a fresh replay.

    Use dry_run=true to preview changes without making them.

    Args:
        request: Setup parameters including session_id, dry_run, and server overrides.
    """
    try:
        # Build server overrides dict
        server_overrides = {}
        if request.server_ip:
            server_overrides["server_ip"] = request.server_ip
        if request.domain:
            server_overrides["domain"] = request.domain
        if request.username:
            server_overrides["username"] = request.username
        if request.password:
            server_overrides["password"] = request.password
        if request.tree_name:
            server_overrides["tree_name"] = request.tree_name

        result = service.setup_infrastructure(
            session_id=request.session_id,
            capture_path=request.capture_path,
            file_filter=request.file_filter,
            dry_run=request.dry_run,
            force=request.force,
            server_overrides=server_overrides if server_overrides else None,
        )
        return SetupResult(**result)
    except SMBReplayServiceError as e:
        if e.code == "SESSION_NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.message) from e
        raise HTTPException(status_code=400, detail=e.message) from e


@router.post("/execute", response_model=ReplayResult)
def execute_replay(
    request: ReplayExecuteRequest,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> ReplayResult:
    """Execute a replay operation.

    Replays all SMB2 operations from the specified session against
    the configured SMB server.

    This is a synchronous operation that may take significant time
    depending on the number of operations.

    Args:
        request: Replay parameters including session_id, server overrides, and options.
    """
    try:
        # Build server overrides dict
        server_overrides = {}
        if request.server_ip:
            server_overrides["server_ip"] = request.server_ip
        if request.domain:
            server_overrides["domain"] = request.domain
        if request.username:
            server_overrides["username"] = request.username
        if request.password:
            server_overrides["password"] = request.password
        if request.tree_name:
            server_overrides["tree_name"] = request.tree_name

        result = service.execute_replay(
            session_id=request.session_id,
            capture_path=request.capture_path,
            file_filter=request.file_filter,
            validate_first=request.validate_first,
            enable_ping=request.enable_ping,
            server_overrides=server_overrides if server_overrides else None,
        )
        return ReplayResult(**result)
    except SMBReplayServiceError as e:
        if e.code == "SESSION_NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.message) from e
        raise HTTPException(status_code=400, detail=e.message) from e
