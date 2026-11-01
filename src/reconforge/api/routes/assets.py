"""Asset inventory and exposed network services routes."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from reconforge.api.dependencies import get_db, get_repository, verify_api_key
from reconforge.api.models import AssetDetailResponse, AssetListItem, ServiceDetailResponse
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssetRecord, FindingRecord

router = APIRouter(
    prefix="/assets", tags=["Asset Inventory"], dependencies=[Depends(verify_api_key)]
)


@router.get("", response_model=list[AssetListItem], summary="List inventoried assets")
async def list_assets(
    query: str | None = Query(None, description="Search by IP address or hostname"),
    criticality: str | None = Query(
        None, description="Filter by criticality (critical, high, medium, low)"
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: DatabaseManager = Depends(get_db),
) -> list[AssetListItem]:
    """Retrieve normalized network assets with exposed service counts and risk scores."""
    with db.session() as session:
        stmt = (
            select(AssetRecord)
            .options(selectinload(AssetRecord.services))
            .order_by(AssetRecord.last_observed_at.desc())
        )
        if criticality:
            stmt = stmt.where(AssetRecord.criticality == criticality.lower())
        if query:
            q = f"%{query}%"
            stmt = stmt.where(
                (AssetRecord.ip_address.like(q)) | (AssetRecord.observed_hostnames.like(q))
            )

        stmt = stmt.limit(limit).offset(offset)
        assets = session.execute(stmt).scalars().all()

        return [
            AssetListItem(
                id=a.id,
                ip_address=a.ip_address,
                address_family=a.address_family,
                observed_hostnames=a.observed_hostnames or [],
                criticality=a.criticality,
                services_count=len(a.services),
                risk_score=a.risk_score,
                last_observed_at=a.last_observed_at,
            )
            for a in assets
        ]


@router.get("/{id_or_ip}", response_model=AssetDetailResponse, summary="Get asset details")
async def get_asset(
    id_or_ip: str,
    repo: AssetRepository = Depends(get_repository),
    db: DatabaseManager = Depends(get_db),
) -> AssetDetailResponse:
    """Retrieve complete asset details including exposed services, banner snippets, and findings."""
    asset = repo.get_asset(id_or_ip)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{id_or_ip}' not found in inventory.",
        )

    with db.session() as session:
        findings_count = (
            session.execute(
                select(func.count(FindingRecord.id)).where(FindingRecord.asset_id == asset.id)
            ).scalar()
            or 0
        )

    services_resp = [
        ServiceDetailResponse(
            id=s.id,
            port=s.port,
            protocol=s.protocol,
            service_name=s.service_name,
            product=s.product,
            version=s.version,
            confidence=s.confidence,
            banner_snippet=s.banner_snippet,
            cpe_candidate=s.cpe_candidate,
            tls_metadata=s.tls_metadata,
            first_observed_at=s.first_observed_at,
            last_observed_at=s.last_observed_at,
        )
        for s in asset.services
    ]

    return AssetDetailResponse(
        id=asset.id,
        ip_address=asset.ip_address,
        address_family=asset.address_family,
        observed_hostnames=asset.observed_hostnames or [],
        asset_type=asset.asset_type,
        criticality=asset.criticality,
        first_observed_at=asset.first_observed_at,
        last_observed_at=asset.last_observed_at,
        discovery_sources=asset.discovery_sources or [],
        risk_score=asset.risk_score,
        risk_breakdown=asset.risk_breakdown,
        services=services_resp,
        findings_count=findings_count,
    )
