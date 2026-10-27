"""Integration test: End-to-end scan observation, exposure assessment, and finding lifecycle."""

import pytest

from reconforge.assessment.engine import ExposureEngine
from reconforge.core.enums import ObservationConfidence, PortState, ScanStatus
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.fingerprinting.models import ServiceFingerprint, TLSMetadata
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager


@pytest.fixture
def test_setup() -> tuple[DatabaseManager, AssetRepository, ExposureEngine, str]:
    db = DatabaseManager("sqlite:///:memory:")
    repo = AssetRepository(db)
    engine = ExposureEngine(include_builtin=True)
    scan_id = "test-assessment-flow-uuid"

    observations = [
        PortObservation(
            target_ip="10.50.0.10",
            hostname="legacy-switch.internal",
            port=23,
            state=PortState.OPEN,
            response_time_ms=0.8,
            service=ServiceFingerprint(
                service_name="telnet",
                confidence=ObservationConfidence.HIGH,
                banner_snippet="Cisco IOS Telnet Service",
            ),
        ),
        PortObservation(
            target_ip="10.50.0.10",
            hostname="legacy-switch.internal",
            port=3306,
            state=PortState.OPEN,
            response_time_ms=1.1,
            service=ServiceFingerprint(
                service_name="mysql",
                product="MySQL",
                version="8.0.32",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
        PortObservation(
            target_ip="10.50.0.10",
            hostname="legacy-switch.internal",
            port=443,
            state=PortState.OPEN,
            response_time_ms=2.0,
            service=ServiceFingerprint(
                service_name="https",
                product="nginx",
                version="1.18.0",
                confidence=ObservationConfidence.HIGH,
                tls_info=TLSMetadata(
                    protocol_version="TLSv1.3",
                    cipher_suite="TLS_AES_256_GCM_SHA384",
                    is_expired=True,
                    is_self_signed=True,
                ),
            ),
        ),
    ]

    summary = ScanSummary(
        scan_id=scan_id,
        targets_assessed=1,
        probes_attempted=3,
        open_count=3,
        closed_count=0,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.2,
        status=ScanStatus.COMPLETED,
    )

    repo.record_scan_results(
        assessment_id=scan_id,
        scope_config={"targets": ["10.50.0.10"]},
        scanner_version="0.4.0",
        observations=observations,
        summary=summary,
    )

    return db, repo, engine, scan_id


def test_assessment_flow_end_to_end(test_setup):
    db, repo, engine, scan_id = test_setup

    # 1. Evaluate assessment exposures
    findings = engine.evaluate_assessment(scan_id, db, persist=True)
    assert len(findings) >= 4

    rule_ids = {f.rule_id for f in findings}
    assert "EXP-CLEARTEXT-TELNET" in rule_ids
    assert "EXP-DB-MYSQL" in rule_ids
    assert "EXP-TLS-EXPIRED" in rule_ids
    assert "EXP-TLS-SELFSIGNED" in rule_ids

    # 2. Query repository findings
    persisted_findings = repo.list_findings(assessment_id=scan_id)
    assert len(persisted_findings) == len(findings)

    # 3. Filter by severity
    high_findings = repo.list_findings(assessment_id=scan_id, severity="high")
    assert any(f.rule_id == "EXP-CLEARTEXT-TELNET" for f in high_findings)

    # 4. Prefix lookup
    first_finding = persisted_findings[0]
    fetched = repo.get_finding(first_finding.id[:8])
    assert fetched is not None
    assert fetched.id == first_finding.id

    # 5. Finding lifecycle state transition
    updated = repo.update_finding_state(first_finding.id[:8], "accepted_risk")
    assert updated is not None
    assert updated.state == "accepted_risk"

    re_fetched = repo.get_finding(first_finding.id)
    assert re_fetched.state == "accepted_risk"
