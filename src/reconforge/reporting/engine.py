"""Centralized reporting engine coordinating posture calculation, report compilation, and multi-format exports."""

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reconforge.core.enums import ReportFormat
from reconforge.inventory.repository import AssetRepository
from reconforge.reporting.generators import (
    CSVReportGenerator,
    HTMLReportGenerator,
    JSONReportGenerator,
    MarkdownReportGenerator,
)
from reconforge.reporting.models import (
    AssessmentReport,
    AssetSummary,
    FindingSummary,
    ReportMetadata,
)
from reconforge.scoring.calculator import AttackSurfaceCalculator
from reconforge.storage.models import AssessmentRecord

logger = logging.getLogger("reconforge.reporting.engine")


class ReportEngine:
    """Compiles and exports comprehensive security assessment reports."""

    def __init__(self, calculator: AttackSurfaceCalculator | None = None):
        self.calculator = calculator or AttackSurfaceCalculator()

    def build_report(
        self,
        assessment_id: str,
        repository: AssetRepository,
        title: str = "ReconForge Attack-Surface Exposure & Security Intelligence Report",
        organization: str = "Authorized Security Operations",
        classification: str = "CONFIDENTIAL - INTERNAL SECURITY ASSESSMENT",
    ) -> AssessmentReport:
        """Compile a complete, self-contained assessment report."""
        # 1. Compute assessment risk posture and per-asset scores
        posture = self.calculator.calculate_assessment_posture(assessment_id, repository)

        # 2. Retrieve assessment metadata and scope
        with repository.db.session() as session:
            assessment = session.get(AssessmentRecord, posture.assessment_id)
            if not assessment:
                raise ValueError(f"Assessment '{posture.assessment_id}' could not be loaded.")

            scope_config = dict(assessment.scope_config or {})
            coverage_metrics = dict(assessment.coverage_metrics or {})
            scanner_version = assessment.scanner_version or "0.6.0"

        # 3. Retrieve findings
        finding_records = repository.list_findings(assessment_id=posture.assessment_id)
        findings_summary: list[FindingSummary] = []
        roadmap: list[dict[str, Any]] = []

        # Map findings into report models
        for f in finding_records:
            target_ip = f.asset.ip_address if f.asset else "-"
            target_port = f.service.port if f.service else None
            pri_val = f.priority.upper() if f.priority else "P4"

            f_sum = FindingSummary(
                id=f.id,
                rule_id=f.rule_id,
                cve_id=f.cve_id,
                title=f.title,
                severity=f.severity,
                priority=pri_val,
                state=f.state,
                target_ip=target_ip,
                port=target_port,
                description=f.description,
                remediation_guidance=f.remediation_guidance,
                evidence=f.evidence or {},
            )
            findings_summary.append(f_sum)

            if f.remediation_guidance:
                target_label = target_ip + (f":{target_port}" if target_port else "")
                roadmap.append(
                    {
                        "priority": pri_val,
                        "target": target_label,
                        "title": f.title,
                        "action": f.remediation_guidance,
                    }
                )

        # Order roadmap by Priority (P1 first)
        roadmap.sort(key=lambda r: r.get("priority", "P5"))

        # 4. Map assets
        assets_summary: list[AssetSummary] = []
        asset_score_map = {a.asset_id: a for a in posture.asset_scores}

        raw_assets = repository.list_assets(limit=500)
        for a in raw_assets:
            score_data = asset_score_map.get(a.id)
            if not score_data and not a.services:
                continue

            open_ports = [s.port for s in (a.services or []) if s.port > 0]
            asset_findings_count = sum(1 for f in findings_summary if f.target_ip == a.ip_address)

            assets_summary.append(
                AssetSummary(
                    id=a.id,
                    ip_address=a.ip_address,
                    criticality=a.criticality,
                    risk_score=score_data.score if score_data else 0.0,
                    risk_level=score_data.risk_level if score_data else "NEGLIGIBLE",
                    services_count=len(open_ports),
                    open_ports=open_ports,
                    findings_count=asset_findings_count,
                )
            )

        assets_summary.sort(key=lambda a: a.risk_score, reverse=True)

        # 5. Build Metadata
        metadata = ReportMetadata(
            title=title,
            assessment_id=posture.assessment_id,
            generated_at=datetime.now(UTC),
            scanner_version=scanner_version,
            classification=classification,
            organization=organization,
        )

        return AssessmentReport(
            metadata=metadata,
            scope_config=scope_config,
            coverage_metrics=coverage_metrics,
            risk_posture=posture,
            assets=assets_summary,
            findings=findings_summary,
            remediation_roadmap=roadmap,
        )

    def export_report(
        self,
        report: AssessmentReport,
        format: ReportFormat | str,
        output_path: str | Path | None = None,
    ) -> str:
        """Render report into target format and optionally write to filesystem."""
        fmt_str = format.value if isinstance(format, ReportFormat) else str(format).lower()

        if fmt_str == ReportFormat.JSON.value:
            content = JSONReportGenerator.generate(report)
        elif fmt_str == ReportFormat.MARKDOWN.value:
            content = MarkdownReportGenerator.generate(report)
        elif fmt_str == ReportFormat.CSV.value:
            content = CSVReportGenerator.generate(report)
        elif fmt_str == ReportFormat.HTML.value:
            content = HTMLReportGenerator.generate(report)
        else:
            raise ValueError(f"Unsupported report format: '{format}'")

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            logger.info("Exported %s report to '%s'", fmt_str.upper(), p)

        return content
