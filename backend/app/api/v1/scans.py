import logging
from uuid import uuid4

from fastapi import APIRouter, status

from app.schemas.common import ErrorResponse
from app.schemas.scans import ScanRequest, ScanResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    responses={422: {"model": ErrorResponse}},
)
def create_scan(request: ScanRequest) -> ScanResponse:
    """Validate and acknowledge a scan request.

    Package retrieval and analysis are not implemented, and the scan is not stored.
    """
    scan_id = uuid4()
    logger.info(
        "scan accepted scan_id=%s ecosystem=%s package=%s version=%s",
        scan_id,
        request.ecosystem.value,
        request.package_name,
        request.version,
    )
    return ScanResponse(
        scan_id=scan_id,
        ecosystem=request.ecosystem,
        package_name=request.package_name,
        version=request.version,
    )
