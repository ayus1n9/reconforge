"""Unit tests for multi-format report engine and generators."""

import json
from pathlib import Path

import pytest

from reconforge.core.enums import ReportFormat
from reconforge.inventory.repository import AssetRepository
from reconforge.reporting.engine import ReportEngine
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
from reconforge.scoring.models import AssessmentRiskPosture
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import (
    AssessmentRecord,
    AssetRecord,
    FindingRecord,
    ServiceRecord,
)


@pytest.fixture
def sample_report() -> AssessmentReport:
    metadata = ReportMetadata(
        title="Test Attack-Surface Assessment Report",
        organization="Acme Defense Lab",
        assessment_id="asm-test-12345",
        scanner_version="0.6.0",
        generated_at="2026-10-30T12:00:00Z",
    )
    posture = AssessmentRiskPosture(
        assessment_id="asm-test-12345",
        overall_score=72.5,
        risk_level="HIGH",
        assessed_assets_count=2,
        assets_at_risk_count=2,
        priority_distribution={"P1": 1, "P2": 1, "P3": 1, "P4": 0, "P5": 0},
        severity_distribution={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFORMATIONAL": 0},
        key_exposure_drivers=[
            "Critical RCE vulnerability present",
            "Exposed Redis database without auth",
        ],
    )
    findings = [
        FindingSummary(
            id="fnd-1",
            rule_id="RULE-APACHE-CVE-2021-41773",
            cve_id="CVE-2021-41773",
            title="Apache Path Traversal and RCE",
            severity="critical",
            priority="P1",
            state="confirmed",
            target_ip="192.168.1.100",
            port=80,
            description="Remote code execution via path traversal in Apache 2.4.49.",
            remediation_guidance="Upgrade Apache HTTP Server to 2.4.51 or later immediately.",
            evidence={"is_known_exploited": True},
        ),
        FindingSummary(
            id="fnd-2",
            rule_id="RULE-REDIS-UNAUTH",
            cve_id=None,
            title="Unauthenticated Redis Server Exposed",
            severity="high",
            priority="P2",
            state="confirmed",
            target_ip="192.168.1.101",
            port=6379,
            description="Redis datastore accessible without credentials.",
            remediation_guidance="Bind Redis to 127.0.0.1 and enable requirepass authentication.",
            evidence={},
        ),
        FindingSummary(
            id="fnd-3",
            rule_id="RULE-CLEARTEXT-TELNET",
            cve_id=None,
            title="Cleartext Telnet Service Exposed",
            severity="medium",
            priority="P3",
            state="confirmed",
            target_ip="192.168.1.100",
            port=23,
            description="Telnet service exposes cleartext credentials.",
            remediation_guidance="Disable telnet and migrate to SSHv2.",
            evidence={},
        ),
    ]
    assets = [
        AssetSummary(
            id="ast-1",
            ip_address="192.168.1.100",
            criticality="high",
            risk_score=85.0,
            risk_level="CRITICAL",
            services_count=2,
            open_ports=[23, 80],
            findings_count=2,
        ),
        AssetSummary(
            id="ast-2",
            ip_address="192.168.1.101",
            criticality="medium",
            risk_score=60.0,
            risk_level="HIGH",
            services_count=1,
            open_ports=[6379],
            findings_count=1,
        ),
    ]
    roadmap = [
        {
            "priority": "P1",
            "target": "192.168.1.100:80",
            "action": "Upgrade Apache HTTP Server to 2.4.51",
        },
        {
            "priority": "P2",
            "target": "192.168.1.101:6379",
            "action": "Bind Redis to localhost and set password",
        },
    ]
    return AssessmentReport(
        metadata=metadata,
        risk_posture=posture,
        assets=assets,
        findings=findings,
        remediation_roadmap=roadmap,
    )


class TestJSONReportGenerator:
    """Validate JSON serialization of assessment reports."""

    def test_json_generation_roundtrip(self, sample_report: AssessmentReport) -> None:
        generator = JSONReportGenerator()
        json_output = generator.generate(sample_report)

        assert isinstance(json_output, str)
        parsed = json.loads(json_output)

        assert parsed["metadata"]["title"] == sample_report.metadata.title
        assert parsed["risk_posture"]["overall_score"] == 72.5
        assert len(parsed["findings"]) == 3
        assert len(parsed["assets"]) == 2

        # Model validation
        restored = AssessmentReport.model_validate(parsed)
        assert restored.metadata.assessment_id == sample_report.metadata.assessment_id


class TestMarkdownReportGenerator:
    """Validate GitHub Flavored Markdown report generation."""

    def test_markdown_structure_and_sections(self, sample_report: AssessmentReport) -> None:
        generator = MarkdownReportGenerator()
        md = generator.generate(sample_report)

        assert "# Test Attack-Surface Assessment Report" in md
        assert "## 1. Executive Risk Posture" in md
        assert "Remediation Urgency Breakdown" in md
        assert "## 2. Assessed Asset Inventory" in md
        assert "## 3. Prioritized Security Findings" in md
        assert "## 4. Prioritized Remediation Roadmap" in md

        # Posture table checks
        assert "72.5 / 100.0" in md
        assert "HIGH" in md

        # Findings content
        assert "Apache Path Traversal and RCE" in md
        assert "CVE-2021-41773" in md
        assert "Unauthenticated Redis Server Exposed" in md


class TestCSVReportGenerator:
    """Validate tabular findings CSV export."""

    def test_csv_headers_and_rows(self, sample_report: AssessmentReport) -> None:
        generator = CSVReportGenerator()
        csv_text = generator.generate(sample_report)

        lines = [line.strip() for line in csv_text.strip().splitlines() if line.strip()]
        header = lines[0]
        assert "Priority" in header
        assert "Severity" in header
        assert "Title" in header
        assert "Rule ID" in header
        assert "Target IP" in header
        assert "CVE ID" in header
        assert "Remediation Guidance" in header

        # 1 header + 3 findings = 4 lines
        assert len(lines) == 4
        assert "P1" in lines[1]
        assert "CVE-2021-41773" in lines[1]
        assert "192.168.1.100" in lines[1]


class TestHTMLReportGenerator:
    """Validate self-contained, dependency-free HTML5 report generation."""

    def test_html_structure_and_self_containment(self, sample_report: AssessmentReport) -> None:
        generator = HTMLReportGenerator()
        html = generator.generate(sample_report)

        assert "<!DOCTYPE html>" in html
        assert '<html lang="en">' in html
        assert "<style>" in html
        assert "</style>" in html

        # Verify ZERO external web dependencies
        assert "http://" not in html
        assert "https://" not in html
        assert "cdnjs.cloudflare.com" not in html
        assert "unpkg.com" not in html

        # Verify key presentation elements
        assert "72.5" in html
        assert "HIGH" in html
        assert "P1" in html
        assert "Apache Path Traversal and RCE" in html
        assert "Unauthenticated Redis Server Exposed" in html
        assert "Acme Defense Lab" in html


class TestReportEngine:
    """Validate ReportEngine build and export workflows with SQLite repository."""

    def test_report_engine_build_and_export(self, tmp_path: Path) -> None:
        db_mgr = DatabaseManager("sqlite:///:memory:")
        db_mgr.init_db()
        repo = AssetRepository(db_mgr)
        engine = ReportEngine()

        assessment_id = "asm-engine-test"
        with db_mgr.session() as session:
            session.add(
                AssessmentRecord(
                    id=assessment_id,
                    scope_config={"allowed_targets": ["10.0.0.1"]},
                    scanner_version="0.6.0",
                    status="completed",
                )
            )
            session.add(AssetRecord(id="ast-1", ip_address="10.0.0.1", criticality="high"))
            session.add(
                ServiceRecord(
                    id="srv-1",
                    asset_id="ast-1",
                    port=443,
                    service_name="https",
                    product="nginx",
                    version="1.18.0",
                )
            )
            session.add(
                FindingRecord(
                    id="fnd-1",
                    assessment_id=assessment_id,
                    asset_id="ast-1",
                    rule_id="RULE-TLS-WEAK",
                    title="Weak TLS Configuration",
                    description="Outdated TLS cipher suites enabled.",
                    severity="medium",
                    state="confirmed",
                    evidence={"ip_address": "10.0.0.1", "port": 443},
                )
            )

        report = engine.build_report(
            assessment_id=assessment_id,
            repository=repo,
            title="Automated Test Report",
            organization="QA Engine",
        )

        assert report.metadata.assessment_id == assessment_id
        assert len(report.assets) == 1
        assert len(report.findings) == 1
        assert report.risk_posture.assessed_assets_count == 1

        # Test export to file
        out_html = tmp_path / "report.html"
        content = engine.export_report(report, format=ReportFormat.HTML, output_path=str(out_html))
        assert out_html.exists()
        assert out_html.read_text(encoding="utf-8") == content
