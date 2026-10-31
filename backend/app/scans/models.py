from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import UUID

from app.schemas.scans import (
    Ecosystem,
    ScanReportResponse,
    ScanStage,
    ScanState,
)


@dataclass
class ScanRecord:
    scan_id: UUID
    ecosystem: Ecosystem
    package_name: str
    version: str
    status: ScanState
    stage: ScanStage
    progress_percent: int
    message: str
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    report: ScanReportResponse | None = None
    work_dir: Path | None = None
