"""Assessment snapshot export and untrusted import validation routes."""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from reconforge.api.dependencies import get_repository, get_snapshot_manager, verify_api_key
from reconforge.api.models import SnapshotImportResponse
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import AssessmentSnapshot, SnapshotManager

router = APIRouter(
    prefix="/snapshots", tags=["Assessment Snapshots"], dependencies=[Depends(verify_api_key)]
)


@router.get("/export/{assessment_id}", summary="Export assessment snapshot")
async def export_snapshot(
    assessment_id: str,
    repo: AssetRepository = Depends(get_repository),
    snapshot_manager: SnapshotManager = Depends(get_snapshot_manager),
) -> Response:
    """Export a versioned assessment snapshot document (Schema v1.1.0) with embedded findings."""
    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    try:
        snapshot = snapshot_manager.export_snapshot(record.id)
        content = snapshot if isinstance(snapshot, str) else snapshot.model_dump_json(indent=2)
        filename = f"reconforge-snapshot-{record.id[:8]}.json"

        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Snapshot export failed: {err}",
        ) from err


@router.post("/import", response_model=SnapshotImportResponse, summary="Import assessment snapshot")
async def import_snapshot(
    snapshot: AssessmentSnapshot,
    snapshot_manager: SnapshotManager = Depends(get_snapshot_manager),
) -> SnapshotImportResponse:
    """Import and validate an external snapshot document with strict schema and input sanitization."""
    try:
        record = snapshot_manager.import_snapshot(snapshot.model_dump(mode="json"))
        return SnapshotImportResponse(
            imported_assessment_id=record.id,
            assessment_name=record.name,
            assets_count=len(snapshot.assets),
            services_count=sum(len(a.services) for a in snapshot.assets),
            findings_count=len(snapshot.findings),
            message="Snapshot imported successfully.",
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Snapshot import failed: {err}",
        ) from err
