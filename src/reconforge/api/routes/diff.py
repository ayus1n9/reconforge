"""Coverage-aware assessment differencing and change detection routes."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from reconforge.api.dependencies import get_differencer, get_repository, verify_api_key
from reconforge.api.models import DiffRequest
from reconforge.diffing.engine import AssessmentDifferencer
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import AssessmentSnapshot

router = APIRouter(
    prefix="/diff", tags=["Assessment Differencing"], dependencies=[Depends(verify_api_key)]
)


class SnapshotDiffRequest(BaseModel):
    """Payload containing two assessment snapshots for air-gapped comparison."""

    base_snapshot: AssessmentSnapshot = Field(..., description="Baseline assessment snapshot")
    target_snapshot: AssessmentSnapshot = Field(..., description="Target comparison snapshot")


@router.post("", summary="Diff two assessment runs by ID")
async def diff_assessments(
    req: DiffRequest,
    repo: AssetRepository = Depends(get_repository),
    differencer: AssessmentDifferencer = Depends(get_differencer),
) -> dict[str, Any]:
    """Compute coverage-aware state transitions, scope overlap, and risk shifts between two assessments."""
    base = repo.get_assessment(req.base_id)
    if not base:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline assessment '{req.base_id}' not found.",
        )

    target = repo.get_assessment(req.target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target assessment '{req.target_id}' not found.",
        )

    try:
        diff = differencer.diff_assessments(base.id, target.id, repo)
        return diff.model_dump(mode="json")
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Differencing computation failed: {err}",
        ) from err


@router.post("/snapshots", summary="Diff two uploaded assessment snapshots")
async def diff_snapshots(
    req: SnapshotDiffRequest,
    differencer: AssessmentDifferencer = Depends(get_differencer),
) -> dict[str, Any]:
    """Compute air-gapped coverage-aware differencing directly between two uploaded snapshot documents."""
    try:
        diff = differencer.diff_snapshots(req.base_snapshot, req.target_snapshot)
        return diff.model_dump(mode="json")
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Snapshot differencing failed: {err}",
        ) from err
