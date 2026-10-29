"""Unit tests for service vulnerability correlation engine and database finding persistence."""

from reconforge.core.enums import FindingState, ObservationConfidence, PortState, SeverityLevel
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.correlator import VulnerabilityCorrelator
from reconforge.intelligence.models import CVEMatchLevel
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager


def test_correlate_service_clean_version_match():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)
    correlator = VulnerabilityCorrelator(cache=cache)

    results = correlator.correlate_service(
        service_name="ssh",
        product="OpenSSH",
        version="8.9p1",
        banner="SSH-2.0-OpenSSH_8.9p1",
    )
    cve_ids = [r.cve.cve_id for r in results]
    assert "CVE-2024-6387" in cve_ids
    assert "CVE-2023-48795" in cve_ids

    regresshion = next(r for r in results if r.cve.cve_id == "CVE-2024-6387")
    assert regresshion.match_level == CVEMatchLevel.STRONG_CANDIDATE
    assert "squarely within" in regresshion.evidence_rationale


def test_correlate_service_distro_backport_calibration():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)
    correlator = VulnerabilityCorrelator(cache=cache)

    results = correlator.correlate_service(
        service_name="ssh",
        product="OpenSSH",
        version="8.9p1",
        banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    )
    regresshion = next(r for r in results if r.cve.cve_id == "CVE-2024-6387")
    assert regresshion.match_level == CVEMatchLevel.MANUAL_VERIFICATION_REQUIRED
    assert "backported" in regresshion.evidence_rationale


def test_correlate_service_patched_version_no_false_positives():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)
    correlator = VulnerabilityCorrelator(cache=cache)

    # Apache 2.4.58 is not vulnerable to CVE-2021-41773
    results = correlator.correlate_service(
        service_name="http",
        product="Apache httpd",
        version="2.4.58",
    )
    assert len(results) == 0


def test_correlate_assessment_services_and_record_findings():
    db = DatabaseManager("sqlite:///:memory:")
    repo = AssetRepository(db)
    cache = VulnerabilityCache(db)
    correlator = VulnerabilityCorrelator(cache=cache)

    # 1. Record an assessment with a vulnerable service
    scan_summary = ScanSummary(
        scan_id="test-scan-cve-001",
        targets_assessed=1,
        probes_attempted=1,
        open_count=1,
        closed_count=0,
        timeout_count=0,
        filtered_count=0,
        unreachable_count=0,
        error_count=0,
        status="completed",
        duration_seconds=1.0,
    )
    obs = PortObservation(
        target_ip="192.168.1.50",
        port=22,
        state=PortState.OPEN,
        service=ServiceFingerprint(
            service_name="ssh",
            product="OpenSSH",
            version="8.9p1",
            confidence=ObservationConfidence.HIGH,
            banner_snippet="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        ),
    )
    repo.record_scan_results(
        assessment_id="test-scan-cve-001",
        scope_config={"allowed_targets": ["192.168.1.50"]},
        scanner_version="0.5.0",
        observations=[obs],
        summary=scan_summary,
    )

    # 2. Correlate assessment services
    corr_map = correlator.correlate_assessment_services(
        assessment_id="test-scan-cve-001",
        repository=repo,
        record_findings=True,
    )
    assert len(corr_map) == 1

    # 3. Verify finding recorded in repository
    findings = repo.list_findings(assessment_id="test-scan-cve-001")
    assert len(findings) >= 2

    cve_findings = [f for f in findings if f.cve_id == "CVE-2024-6387"]
    assert len(cve_findings) == 1
    f = cve_findings[0]
    assert f.severity == SeverityLevel.HIGH.value
    # Because Ubuntu backport was detected, state must be NEEDS_REVIEW
    assert f.state == FindingState.NEEDS_REVIEW.value
    assert f.evidence["match_level"] == CVEMatchLevel.MANUAL_VERIFICATION_REQUIRED.value
    assert "Ubuntu-3ubuntu0.10" in f.evidence["evidence_rationale"]
