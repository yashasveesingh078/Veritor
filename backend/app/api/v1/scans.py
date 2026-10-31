import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.scans.manager import (
    ScanNotFoundError,
    ScanNotReadyError,
    get_scan_manager,
)
from app.schemas.common import ErrorResponse
from app.schemas.scans import (
    ScanDiffsResponse,
    ScanFilesResponse,
    ScanFindingsResponse,
    ScanReportResponse,
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
    responses={422: {"model": ErrorResponse}},
)
async def create_scan(request: ScanRequest) -> ScanResponse:
    """Validate and initiate a package integrity scan."""
    record = await get_scan_manager().create_scan(request)
    return ScanResponse(
        scan_id=record.scan_id,
        status="accepted",
        ecosystem=record.ecosystem,
        package_name=record.package_name,
        version=record.version,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    responses={404: {"model": ErrorResponse}},
)
def get_scan_status(scan_id: UUID) -> ScanStatusResponse:
    """Get the current status and progress of a scan."""
    try:
        return get_scan_manager().get_status(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def get_scan_report(scan_id: UUID) -> ScanReportResponse:
    """Get the complete integrity analysis report."""
    try:
        return get_scan_manager().get_report(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get(
    "/{scan_id}/findings",
    response_model=ScanFindingsResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def get_scan_findings(scan_id: UUID) -> ScanFindingsResponse:
    """Get security findings, gaps, and AI investigation explanations."""
    try:
        return get_scan_manager().get_findings(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get(
    "/{scan_id}/files",
    response_model=ScanFilesResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def get_scan_files(scan_id: UUID) -> ScanFilesResponse:
    """Get file inventory and source comparison classifications."""
    try:
        return get_scan_manager().get_files(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get(
    "/{scan_id}/diffs",
    response_model=ScanDiffsResponse,
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def get_scan_diffs(scan_id: UUID, path: str | None = Query(default=None)) -> ScanDiffsResponse:
    """Get file diffs between package and source repository."""
    try:
        return get_scan_manager().get_diffs(scan_id, path=path)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
