"""Trace/PCAP management endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query

from api.models.trace import IngestRequest, IngestResult, TraceFile, TraceListResponse
from api.services.smbreplay_service import (
    SMBReplayService,
    SMBReplayServiceError,
    get_smbreplay_service,
)

router = APIRouter(prefix="/api/traces", tags=["traces"])


@router.get("", response_model=TraceListResponse)
def list_traces(
    case_id: str | None = Query(None, description="Case ID to list traces for"),
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> TraceListResponse:
    """List available trace files.

    Lists all valid PCAP/PCAPNG files in the specified case directory.
    Files are validated using tshark before being included in the list.

    Args:
        case_id: Case ID to search. Uses configured case_id if not provided.
    """
    try:
        traces = service.list_traces(case_id)
        return TraceListResponse(
            traces=[TraceFile(**t) for t in traces],
            case_id=case_id or service.system.config.get_case_id(),
            total=len(traces),
        )
    except SMBReplayServiceError as e:
        raise HTTPException(status_code=400, detail=e.message) from e


@router.post("/ingest", response_model=IngestResult)
def ingest_trace(
    request: IngestRequest,
    service: SMBReplayService = Depends(get_smbreplay_service),
) -> IngestResult:
    """Ingest a PCAP file.

    Processes the specified PCAP file using tshark to extract SMB2 sessions.
    Each session is stored as a Parquet file for efficient querying.

    This is a synchronous operation that may take several minutes for large captures.

    Args:
        request: Ingestion parameters including:
            - path: Path to PCAP file (absolute or relative to case folder)
            - force: Re-ingest even if data exists
            - reassembly: Enable TCP reassembly
            - case_id: Case ID for relative paths
    """
    try:
        # Ensure full setup for tshark access
        if not service.ensure_full_setup():
            return IngestResult(
                success=False,
                error="System setup failed - tshark may not be available",
            )

        result = service.ingest_pcap(
            path=request.path,
            force=request.force,
            reassembly=request.reassembly,
            case_id=request.case_id,
        )
        return IngestResult(**result)
    except SMBReplayServiceError as e:
        return IngestResult(success=False, error=e.message)
    except Exception as e:
        return IngestResult(success=False, error=str(e))
