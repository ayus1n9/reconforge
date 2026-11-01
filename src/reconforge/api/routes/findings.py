"""Finding query, detailed inspection, and lifecycle state management routes."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from reconforge.api.dependencies import get_db, get_repository, verify_api_key
from reconforge.api.models import FindingDetailResponse, FindingListItem, FindingStateUpdateRequest
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import FindingRecord

router = APIRouter(
    prefix="/findings", tags=["Findings & Exposures"], dependencies=[Depends(verify_api_key)]
)

ALLOWED_FINDING_STATES = {
    "confirmed",
    "false_positive",
    "accepted_risk",
    "potential_exposure",
    "potential_vulnerability",
    "needs_review",
}


@router.get("", response_model=list[FindingListItem], summary="List security findings")
async def list_findings(
    assessment_id: str | None = Query(None, description="Filter by assessment ID"),
    asset_id: str | None = Query(None, description="Filter by asset ID"),
    severity: str | None = Query(None, description="critical, high, medium, low, info"),
    priority: str | None = Query(None, description="P1, P2, P3, P4, P5"),
    state: str | None = Query(None, description="confirmed, false_positive, accepted_risk, etc."),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
) -> list[FindingListItem]:
    """Query exposure and vulnerability findings across assessments and assets."""
    with db.session() as session:
        stmt = (
            select(FindingRecord)
            .options(selectinload(FindingRecord.asset), selectinload(FindingRecord.service))
            .order_by(FindingRecord.created_at.desc())
        )
        if assessment_id:
            stmt = stmt.where(
                (FindingRecord.assessment_id == assessment_id)
                | (FindingRecord.assessment_id.startswith(assessment_id))
            )
        if asset_id:
            stmt = stmt.where(
                (FindingRecord.asset_id == asset_id) | (FindingRecord.asset_id.startswith(asset_id))
            )
        if severity:
            stmt = stmt.where(FindingRecord.severity == severity.lower())
        if priority:
            stmt = stmt.where(FindingRecord.priority == priority.upper())
        if state:
            stmt = stmt.where(FindingRecord.state == state.lower())

        stmt = stmt.limit(limit).offset(offset)
        findings = session.execute(stmt).scalars().all()

        return [
            FindingListItem(
                id=f.id,
                assessment_id=f.assessment_id,
                asset_id=f.asset_id,
                target_ip=f.asset.ip_address if f.asset else None,
                port=f.service.port if f.service else None,
                rule_id=f.rule_id,
                cve_id=f.cve_id,
                title=f.title,
                severity=f.severity,
                priority=f.priority,
                state=f.state,
                created_at=f.created_at,
            )
            for f in findings
        ]


@router.get("/{finding_id}", response_model=FindingDetailResponse, summary="Get finding details")
async def get_finding(
    finding_id: str,
    repo: AssetRepository = Depends(get_repository),
) -> FindingDetailResponse:
    """Retrieve comprehensive finding information with evidence, CVE mappings, and remediation."""
    f = repo.get_finding(finding_id)
    if not f:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    return FindingDetailResponse(
        id=f.id,
        assessment_id=f.assessment_id,
        asset_id=f.asset_id,
        service_id=f.service_id,
        target_ip=f.asset.ip_address if f.asset else None,
        port=f.service.port if f.service else None,
        protocol=f.service.protocol if f.service else None,
        rule_id=f.rule_id,
        cve_id=f.cve_id,
        title=f.title,
        description=f.description,
        severity=f.severity,
        priority=f.priority,
        state=f.state,
        evidence=f.evidence or {},
        remediation_guidance=f.remediation_guidance,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


@router.patch(
    "/{finding_id}/state",
    response_model=FindingDetailResponse,
    summary="Update finding lifecycle state",
)
async def update_finding_state(
    finding_id: str,
    req: FindingStateUpdateRequest,
    db: DatabaseManager = Depends(get_db),
    repo: AssetRepository = Depends(get_repository),
) -> FindingDetailResponse:
    """Modify finding lifecycle state (e.g., mark as false_positive or accepted_risk)."""
    norm_state = req.state.lower().strip()
    if norm_state not in ALLOWED_FINDING_STATES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid finding state '{req.state}'. Allowed states: "
                f"{', '.join(sorted(ALLOWED_FINDING_STATES))}"
            ),
        )

    with db.session() as session:
        stmt = (
            select(FindingRecord)
            .options(
                selectinload(FindingRecord.asset),
                selectinload(FindingRecord.service),
                selectinload(FindingRecord.assessment),
            )
            .where((FindingRecord.id == finding_id) | (FindingRecord.id.startswith(finding_id)))
        )
        f = session.execute(stmt).scalars().first()
        if not f:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found.",
            )

        f.state = norm_state
        f.updated_at = datetime.now(UTC)
        if req.reason:
            evidence = dict(f.evidence or {})
            history = evidence.get("state_history", [])
            history.append(
                {
                    "from_state": f.state,
                    "to_state": norm_state,
                    "reason": req.reason,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
            evidence["state_history"] = history
            f.evidence = evidence

        session.flush()
        session.refresh(f)

        return FindingDetailResponse(
            id=f.id,
            assessment_id=f.assessment_id,
            asset_id=f.asset_id,
            service_id=f.service_id,
            target_ip=f.asset.ip_address if f.asset else None,
            port=f.service.port if f.service else None,
            protocol=f.service.protocol if f.service else None,
            rule_id=f.rule_id,
            cve_id=f.cve_id,
            title=f.title,
            description=f.description,
            severity=f.severity,
            priority=f.priority,
            state=f.state,
            evidence=f.evidence or {},
            remediation_guidance=f.remediation_guidance,
            created_at=f.created_at,
            updated_at=f.updated_at,
        )
