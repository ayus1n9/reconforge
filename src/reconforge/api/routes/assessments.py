"""Assessment execution management, status monitoring, and lifecycle routes."""

import ipaddress
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select

from reconforge import __version__
from reconforge.api.dependencies import get_db, get_repository, verify_api_key
from reconforge.api.manager import ScanExecutionManager
from reconforge.api.models import (
    AssessmentDetailResponse,
    AssessmentLaunchRequest,
    AssessmentLaunchResponse,
    AssessmentListItem,
    AssessmentProgressResponse,
)
from reconforge.core.exceptions import ScopeViolationError
from reconforge.core.models import ScanConfig, TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, FindingRecord
from reconforge.utils.network import parse_ports

router = APIRouter(
    prefix="/assessments",
    tags=["Assessments"],
    dependencies=[Depends(verify_api_key)],
)


def get_scan_manager(request: Request) -> ScanExecutionManager:
    """Retrieve scan execution manager from application state."""
    if hasattr(request.app.state, "scan_manager"):
        return request.app.state.scan_manager
    manager = ScanExecutionManager()
    request.app.state.scan_manager = manager
    return manager


@router.post(
    "",
    response_model=AssessmentLaunchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Launch network discovery assessment",
)
async def launch_assessment(
    req: AssessmentLaunchRequest,
    db: DatabaseManager = Depends(get_db),
    manager: ScanExecutionManager = Depends(get_scan_manager),
) -> AssessmentLaunchResponse:
    """Authorize and dispatch an asynchronous background attack-surface assessment."""
    try:
        parsed_ports = parse_ports(req.ports)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid port specification: {err}",
        ) from err

    scope = TargetScope(
        allowed_targets=req.targets,
        allowed_ports=req.ports,
        allow_public_targets=req.allow_public,
        lab_mode=True,
    )

    try:
        scope_manager = ScopeManager(scope)
        first_port = parsed_ports[0]
        for t in req.targets:
            t_clean = t.strip()
            try:
                ip_val = ipaddress.ip_address(t_clean)
                scope_manager.validate_target_and_port(ip_val, first_port)
            except ValueError:
                if "/" in t_clean:
                    try:
                        net = ipaddress.ip_network(t_clean, strict=False)
                        scope_manager.validate_target_and_port(net.network_address, first_port)
                    except ValueError:
                        pass

        targets = scope_manager.expand_static_targets()
        if not targets and not scope_manager.allowed_hostnames:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid targets found within authorized scope.",
            )
    except ScopeViolationError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope violation: {err}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope preparation failed: {err}",
        ) from err

    assessment_id = str(uuid4())
    config = ScanConfig(
        timeout_seconds=req.timeout,
        concurrency=req.concurrency,
        rate_limit_per_second=req.rate_limit,
        skip_host_discovery=not req.host_discovery,
        fingerprint_services=req.fingerprint,
        use_nmap=req.use_nmap,
    )

    # Pre-record pending assessment in database
    with db.session() as session:
        record = AssessmentRecord(
            id=assessment_id,
            name=req.name,
            scope_config=scope.model_dump(),
            scanner_version=__version__,
            status="pending",
            start_time=datetime.now(UTC),
            coverage_metrics={"configured_targets": req.targets, "ports": req.ports},
        )
        session.add(record)

    # Launch background scan
    await manager.start_scan(
        assessment_id=assessment_id,
        name=req.name,
        scope=scope,
        config=config,
        assess=req.assess,
        correlate_cves=req.correlate_cves,
        db_mgr=db,
    )

    return AssessmentLaunchResponse(
        assessment_id=assessment_id,
        name=req.name,
        status="running",
        message="Assessment successfully launched in background.",
    )


@router.get("", response_model=list[AssessmentListItem], summary="List assessment runs")
async def list_assessments(
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
) -> list[AssessmentListItem]:
    """Retrieve historical assessment runs with summary statistics."""
    with db.session() as session:
        stmt = select(AssessmentRecord).order_by(AssessmentRecord.start_time.desc())
        if status_filter:
            stmt = stmt.where(AssessmentRecord.status == status_filter.lower())
        stmt = stmt.limit(limit).offset(offset)
        records = session.execute(stmt).scalars().all()

        results = []
        for r in records:
            f_count = (
                session.execute(
                    select(func.count(FindingRecord.id)).where(FindingRecord.assessment_id == r.id)
                ).scalar()
                or 0
            )
            # Estimate assets count from coverage metrics or findings
            assets_count = 0
            if r.coverage_metrics and "total_targets" in r.coverage_metrics:
                assets_count = r.coverage_metrics["total_targets"]

            results.append(
                AssessmentListItem(
                    id=r.id,
                    name=r.name,
                    status=r.status,
                    start_time=r.start_time,
                    end_time=r.end_time,
                    risk_score=r.risk_score,
                    findings_count=f_count,
                    assets_count=assets_count,
                )
            )
        return results


@router.get(
    "/{assessment_id}", response_model=AssessmentDetailResponse, summary="Get assessment details"
)
async def get_assessment(
    assessment_id: str,
    repo: AssetRepository = Depends(get_repository),
    manager: ScanExecutionManager = Depends(get_scan_manager),
    db: DatabaseManager = Depends(get_db),
) -> AssessmentDetailResponse:
    """Retrieve complete assessment metrics, scope configuration, and live progress if active."""
    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    live_prog: AssessmentProgressResponse | None = None
    if record.status in ("pending", "running") and manager.is_running(record.id):
        p = manager.get_progress(record.id)
        if p:
            live_prog = AssessmentProgressResponse(
                assessment_id=record.id,
                status=record.status,
                completed_probes=p.completed_probes,
                total_probes=p.total_probes,
                percent_complete=p.percentage,
                elapsed_seconds=round(manager.get_elapsed_seconds(record.id), 2),
            )

    findings = repo.list_findings(assessment_id=record.id)

    return AssessmentDetailResponse(
        id=record.id,
        name=record.name,
        status=record.status,
        scanner_version=record.scanner_version,
        scope_config=record.scope_config or {},
        start_time=record.start_time,
        end_time=record.end_time,
        coverage_metrics=record.coverage_metrics or {},
        risk_score=record.risk_score,
        risk_posture=record.risk_posture,
        error_summary=record.error_summary,
        live_progress=live_prog,
        findings_count=len(findings),
    )


@router.post("/{assessment_id}/cancel", summary="Cancel active assessment")
async def cancel_assessment(
    assessment_id: str,
    db: DatabaseManager = Depends(get_db),
    manager: ScanExecutionManager = Depends(get_scan_manager),
    repo: AssetRepository = Depends(get_repository),
) -> dict[str, str]:
    """Cooperatively abort an active scan and mark its assessment status as cancelled."""
    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    success = await manager.cancel_scan(record.id, db)
    if not success and record.status not in ("pending", "running"):
        return {
            "message": f"Assessment is already in '{record.status}' state.",
            "assessment_id": record.id,
        }

    return {"message": "Assessment cancelled successfully.", "assessment_id": record.id}


@router.delete("/{assessment_id}", summary="Delete assessment record")
async def delete_assessment(
    assessment_id: str,
    repo: AssetRepository = Depends(get_repository),
    manager: ScanExecutionManager = Depends(get_scan_manager),
) -> dict[str, str]:
    """Delete an assessment run and cascade-delete associated findings."""
    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    if record.status == "running" and manager.is_running(record.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete an assessment that is actively running. Cancel it first.",
        )

    repo.delete_assessment(record.id)
    return {"message": "Assessment deleted successfully.", "assessment_id": record.id}
