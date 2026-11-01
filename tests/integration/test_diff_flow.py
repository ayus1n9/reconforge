"""Integration test: End-to-end multi-assessment lifecycle differencing and risk drift verification."""

from pathlib import Path

from typer.testing import CliRunner

from reconforge.assessment.engine import ExposureEngine
from reconforge.cli import app
from reconforge.core.enums import ObservationConfidence, PortState, ScanStatus
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.diffing.engine import AssessmentDifferencer
from reconforge.diffing.models import (
    ChangeCertainty,
    RiskDirection,
    ScopeOverlapType,
)
from reconforge.fingerprinting.models import ServiceFingerprint, TLSMetadata
from reconforge.inventory.repository import AssetRepository
from reconforge.scoring.calculator import AttackSurfaceCalculator
from reconforge.storage.database import DatabaseManager

runner = CliRunner()


def test_end_to_end_assessment_diff_flow(tmp_path: Path):
    """Verify complete end-to-end assessment comparison with findings remediation and risk reduction."""
    db_file = tmp_path / "integration_diff.db"
    db = DatabaseManager(f"sqlite:///{db_file}")
    repo = AssetRepository(db)
    exposure_engine = ExposureEngine(include_builtin=True)
    score_calculator = AttackSurfaceCalculator()
    differencer = AssessmentDifferencer()

    target_ip = "10.50.0.10"
    base_id = "asm-baseline-flow"
    comp_id = "asm-remediated-flow"

    # =========================================================================
    # 1. Baseline Assessment: Telnet (23), Vulnerable Apache (80), MySQL (3306)
    # =========================================================================
    base_obs = [
        PortObservation(
            target_ip=target_ip,
            port=23,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="telnet",
                confidence=ObservationConfidence.HIGH,
                banner_snippet="Insecure Telnet",
            ),
        ),
        PortObservation(
            target_ip=target_ip,
            port=80,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="http",
                product="Apache httpd",
                version="2.4.49",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
        PortObservation(
            target_ip=target_ip,
            port=3306,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="mysql",
                product="MySQL",
                version="8.0.32",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
    ]
    base_summary = ScanSummary(
        scan_id=base_id,
        targets_assessed=1,
        probes_attempted=3,
        open_count=3,
        closed_count=0,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.15,
        status=ScanStatus.COMPLETED,
    )
    repo.record_scan_results(
        assessment_id=base_id,
        scope_config={"allowed_targets": [target_ip], "allowed_ports": "23,80,443,3306"},
        scanner_version="0.6.0",
        observations=base_obs,
        summary=base_summary,
        assessment_name="Baseline Audit",
    )
    # Run exposure rules
    base_findings = exposure_engine.evaluate_assessment(base_id, db, persist=True)
    assert len(base_findings) >= 2
    # Calculate posture
    base_posture = score_calculator.calculate_assessment_posture(base_id, repo)
    assert base_posture.overall_score > 30.0

    # =========================================================================
    # 2. Remediation Scan: Telnet CLOSED, Apache UPGRADED (2.4.52), HTTPS (443) OPEN
    # =========================================================================
    comp_obs = [
        # Port 23 is definitively closed
        PortObservation(
            target_ip=target_ip,
            port=23,
            state=PortState.CLOSED,
            service=None,
        ),
        PortObservation(
            target_ip=target_ip,
            port=80,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="http",
                product="Apache httpd",
                version="2.4.52",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
        PortObservation(
            target_ip=target_ip,
            port=443,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="https",
                product="nginx",
                version="1.24.0",
                confidence=ObservationConfidence.HIGH,
                tls_info=TLSMetadata(protocol_version="TLSv1.3", is_expired=False),
            ),
        ),
        PortObservation(
            target_ip=target_ip,
            port=3306,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="mysql",
                product="MySQL",
                version="8.0.32",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
    ]
    comp_summary = ScanSummary(
        scan_id=comp_id,
        targets_assessed=1,
        probes_attempted=4,
        open_count=3,
        closed_count=1,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.12,
        status=ScanStatus.COMPLETED,
    )
    repo.record_scan_results(
        assessment_id=comp_id,
        scope_config={"allowed_targets": [target_ip], "allowed_ports": "23,80,443,3306"},
        scanner_version="0.7.0",
        observations=comp_obs,
        summary=comp_summary,
        assessment_name="Post-Remediation Verification Audit",
    )
    # Run exposure rules
    exposure_engine.evaluate_assessment(comp_id, db, persist=True)
    # Calculate posture
    score_calculator.calculate_assessment_posture(comp_id, repo)

    # =========================================================================
    # 3. Differencing Engine Verification
    # =========================================================================
    diff = differencer.diff_assessments(base_id, comp_id, repo)

    # Scope & Coverage
    assert diff.coverage.overlap_type == ScopeOverlapType.IDENTICAL
    assert diff.coverage.is_coverage_complete is True

    # Host stability
    assert len(diff.added_hosts) == 0
    assert len(diff.removed_hosts) == 0
    assert diff.retained_hosts_count == 1

    # Port state transitions
    assert any(
        p.port == 23 and p.certainty == ChangeCertainty.DEFINITIVE for p in diff.closed_ports
    )
    assert any(
        p.port == 443 and p.certainty == ChangeCertainty.DEFINITIVE for p in diff.opened_ports
    )

    # Service upgrade
    upgraded = next((m for m in diff.modified_services if m.port == 80), None)
    assert upgraded is not None
    assert upgraded.is_upgrade is True
    assert upgraded.old_version == "2.4.49"
    assert upgraded.new_version == "2.4.52"

    # Finding remediation
    assert any(f.rule_id == "EXP-CLEARTEXT-TELNET" for f in diff.resolved_findings)

    # Risk posture drift
    assert diff.risk.direction in (RiskDirection.IMPROVED, RiskDirection.STABLE)
    assert diff.risk.score_delta <= 0.0

    # Executive narrative verification
    narrative_text = " ".join(diff.summary_narrative)
    assert "Overall Attack-Surface Risk:" in narrative_text
    assert "Scan Coverage: Identical" in narrative_text
    assert "confirmed closed or filtered" in narrative_text
    assert "verified software version upgrade" in narrative_text

    # =========================================================================
    # 4. CLI Execution Verification
    # =========================================================================
    cli_result = runner.invoke(app, ["diff", base_id, comp_id, "--db-path", str(db_file)])
    assert cli_result.exit_code == 0
    assert "ReconForge Assessment Difference & Change Detection Report" in cli_result.stdout
    assert "software version upgrade" in cli_result.stdout.lower()
    assert "resolved" in cli_result.stdout.lower()

    # JSON CLI verification
    cli_json = runner.invoke(app, ["diff", base_id, comp_id, "--db-path", str(db_file), "--json"])
    assert cli_json.exit_code == 0
    import json

    parsed = json.loads(cli_json.stdout)
    assert any(f["rule_id"] == "EXP-CLEARTEXT-TELNET" for f in parsed["resolved_findings"])
    assert any(m["is_upgrade"] is True for m in parsed["modified_services"])
