"""Attack-surface scoring and risk posture breakdown routes."""

from fastapi import APIRouter, Depends, HTTPException, status

from reconforge.api.dependencies import get_repository, get_scoring_calculator, verify_api_key
from reconforge.api.models import AssessmentPostureResponse, AssetScoreDetailResponse
from reconforge.inventory.repository import AssetRepository
from reconforge.scoring.calculator import AttackSurfaceCalculator

router = APIRouter(
    prefix="/scoring", tags=["Attack-Surface Scoring"], dependencies=[Depends(verify_api_key)]
)


@router.get(
    "/{assessment_id}",
    response_model=AssessmentPostureResponse,
    summary="Get assessment risk posture",
)
async def get_assessment_scoring(
    assessment_id: str,
    repo: AssetRepository = Depends(get_repository),
    calculator: AttackSurfaceCalculator = Depends(get_scoring_calculator),
) -> AssessmentPostureResponse:
    """Retrieve aggregate estate risk posture, score, and priority distribution."""
    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    try:
        posture = calculator.calculate_assessment_posture(record.id, repo)
        risk_lvl = (
            posture.risk_level.value
            if hasattr(posture.risk_level, "value")
            else str(posture.risk_level)
        )
        p_dist = (
            posture.priority_distribution
            if hasattr(posture, "priority_distribution")
            else getattr(posture, "priority_breakdown", {})
        )
        asset_scores = []
        for a in posture.asset_scores:
            a_risk_lvl = a.risk_level.value if hasattr(a.risk_level, "value") else str(a.risk_level)
            crit_val = (
                a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality)
            )
            asset_scores.append(
                {
                    "asset_id": a.asset_id,
                    "ip_address": a.ip_address,
                    "criticality": crit_val,
                    "score": a.score,
                    "risk_level": a_risk_lvl,
                }
            )
        return AssessmentPostureResponse(
            assessment_id=posture.assessment_id,
            risk_score=posture.overall_score,
            risk_level=risk_lvl,
            priority_distribution=p_dist,
            asset_scores=asset_scores,
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate assessment risk posture: {err}",
        ) from err


@router.get(
    "/{assessment_id}/assets/{asset_id}",
    response_model=AssetScoreDetailResponse,
    summary="Get individual asset risk scoring breakdown",
)
async def get_asset_scoring(
    assessment_id: str,
    asset_id: str,
    repo: AssetRepository = Depends(get_repository),
    calculator: AttackSurfaceCalculator = Depends(get_scoring_calculator),
) -> AssetScoreDetailResponse:
    """Retrieve explainable mathematical score calculation and threat multipliers for an asset."""
    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found.",
        )

    findings = repo.list_findings(assessment_id=record.id, asset_id=asset.id)
    score = calculator.calculate_asset_score(asset, asset.services, findings)
    risk_lvl = (
        score.risk_level.value if hasattr(score.risk_level, "value") else str(score.risk_level)
    )
    crit_val = (
        score.criticality.value if hasattr(score.criticality, "value") else str(score.criticality)
    )

    return AssetScoreDetailResponse(
        asset_id=score.asset_id,
        ip_address=score.ip_address,
        criticality=crit_val,
        risk_score=score.score,
        risk_level=risk_lvl,
        exposure_base=score.breakdown.exposure_base,
        findings_weighted=score.breakdown.findings_subtotal,
        criticality_multiplier=score.breakdown.criticality_factor,
        threat_multiplier=score.breakdown.threat_multiplier,
        component_explanations=score.breakdown.component_explanations,
    )
