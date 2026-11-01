"""System diagnostics, health checks, and engine capability status routes."""

import platform
import shutil
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from reconforge import __version__
from reconforge.api.dependencies import get_db, verify_api_key
from reconforge.api.models import HealthResponse, SystemInfoResponse
from reconforge.assessment.engine import ExposureEngine
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, CVECacheRecord, FindingRecord

router = APIRouter(tags=["System & Diagnostics"])


@router.get("/health", response_model=HealthResponse, summary="Service health check")
async def health_check() -> HealthResponse:
    """Lightweight health probe indicating service liveness."""
    return HealthResponse(
        status="ok",
        version=__version__,
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get(
    "/system",
    response_model=SystemInfoResponse,
    dependencies=[Depends(verify_api_key)],
    summary="System information & metrics",
)
async def system_info(db: DatabaseManager = Depends(get_db)) -> SystemInfoResponse:
    """Retrieve system diagnostics, engine capabilities, and persistence metrics."""
    with db.session() as session:
        asset_count = session.execute(select(func.count(AssetRecord.id))).scalar() or 0
        assessment_count = session.execute(select(func.count(AssessmentRecord.id))).scalar() or 0
        finding_count = session.execute(select(func.count(FindingRecord.id))).scalar() or 0
        cve_count = session.execute(select(func.count(CVECacheRecord.cve_id))).scalar() or 0

    engine = ExposureEngine()
    rules_count = len(engine.list_rules())
    nmap_available = shutil.which("nmap") is not None

    return SystemInfoResponse(
        version=__version__,
        python_version=platform.python_version(),
        platform=platform.platform(),
        database_status="connected",
        total_assets=asset_count,
        total_assessments=assessment_count,
        total_findings=finding_count,
        rules_count=rules_count,
        cached_cves_count=cve_count,
        nmap_available=nmap_available,
    )
