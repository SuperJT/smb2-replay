"""Session management endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query

from api.models.session import (
    OperationsRequest,
    OperationsResponse,
    SessionListResponse,
    SessionSummary,
)
from api.services.smbreplay_service import (
    SMBReplayService,
    SMBReplayServiceError,
    get_smbreplay_service,
)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("", response_model=SessionListResponse)
def list_sessions(
    capture_path: str | None = Query(
        None, description="Capture file path to list sessions for"
    ),
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> SessionListResponse:
    """List available sessions.

    Returns all extracted SMB2 sessions for the specified capture file.
    Each session represents a unique SMB2 session ID from the capture.

    Args:
        capture_path: Override configured capture path.
    """
    try:
        sessions = service.list_sessions(capture_path)
        return SessionListResponse(
            sessions=[SessionSummary(**s) for s in sessions],
            capture_path=capture_path or service.system.config.get_capture_path(),
            total=len(sessions),
        )
    except SMBReplayServiceError as e:
        raise HTTPException(status_code=400, detail=e.message) from e


@router.get("/{session_id}", response_model=OperationsResponse)
def get_session(
    session_id: str,
    capture_path: str | None = Query(None, description="Override capture path"),
    file_filter: str | None = Query(None, description="Filter by file path"),
    fields: list[str] | None = Query(None, description="Fields to include"),
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> OperationsResponse:
    """Get session details and operations.

    Returns all operations for the specified session, optionally filtered.

    Args:
        session_id: Session ID (hex format like 0x7602000009fbdaa3) or full file name.
        capture_path: Override configured capture path.
        file_filter: Only include operations for this file path.
        fields: Specific fields to include in operation data.
    """
    try:
        result = service.get_session_operations(
            session_id=session_id,
            capture_path=capture_path,
            file_filter=file_filter,
            fields=fields,
        )
        return OperationsResponse(**result)
    except SMBReplayServiceError as e:
        if e.code == "SESSION_NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.message) from e
        raise HTTPException(status_code=400, detail=e.message) from e


@router.post("/{session_id}/operations", response_model=OperationsResponse)
def get_session_operations(
    session_id: str,
    request: OperationsRequest,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> OperationsResponse:
    """Get session operations with POST body for complex filters.

    Alternative to GET endpoint for passing complex filter parameters.

    Args:
        session_id: Session ID or file name.
        request: Filter and field selection parameters.
    """
    try:
        result = service.get_session_operations(
            session_id=session_id,
            capture_path=request.capture_path,
            file_filter=request.file_filter,
            fields=request.fields,
        )
        return OperationsResponse(**result)
    except SMBReplayServiceError as e:
        if e.code == "SESSION_NOT_FOUND":
            raise HTTPException(status_code=404, detail=e.message) from e
        raise HTTPException(status_code=400, detail=e.message) from e
