"""Multi-format security report generation and export routes."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from reconforge.api.dependencies import get_report_engine, get_repository, verify_api_key
from reconforge.core.enums import ReportFormat
from reconforge.inventory.repository import AssetRepository
from reconforge.reporting.engine import ReportEngine

router = APIRouter(
    prefix="/reports", tags=["Reports & Exports"], dependencies=[Depends(verify_api_key)]
)

MIME_TYPES = {
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.JSON: "application/json",
    ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
    ReportFormat.CSV: "text/csv; charset=utf-8",
}

EXTENSIONS = {
    ReportFormat.HTML: "html",
    ReportFormat.JSON: "json",
    ReportFormat.MARKDOWN: "md",
    ReportFormat.CSV: "csv",
}


@router.get("/{assessment_id}", summary="Generate and download assessment report")
async def generate_report(
    assessment_id: str,
    format_name: str = Query(
        "html", alias="format", description="Report format: html, json, markdown, csv"
    ),
    repo: AssetRepository = Depends(get_repository),
    report_engine: ReportEngine = Depends(get_report_engine),
) -> Response:
    """Generate self-contained executive & technical assessment reports in multiple formats."""
    try:
        report_format = ReportFormat(format_name.lower())
    except ValueError as err:
        valid_formats = ", ".join(f.value for f in ReportFormat)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported report format '{format_name}'. Supported formats: {valid_formats}",
        ) from err

    record = repo.get_assessment(assessment_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    try:
        report = report_engine.build_report(record.id, repo)
        content = report_engine.export_report(report, report_format)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {err}",
        ) from err

    media_type = MIME_TYPES.get(report_format, "text/plain")
    ext = EXTENSIONS.get(report_format, "txt")
    filename = f"reconforge-report-{record.id[:8]}.{ext}"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )
