"""Unit tests for ReconForge assessment differencing and change detection engine."""

from datetime import UTC, datetime

from reconforge.diffing.engine import AssessmentDifferencer
from reconforge.diffing.models import (
    ChangeCertainty,
    RiskDirection,
    ScopeOverlapType,
)
from reconforge.inventory.snapshot import (
    AssessmentSnapshot,
    SnapshotAssessment,
    SnapshotAsset,
    SnapshotFinding,
    SnapshotService,
)


def _make_snapshot(
    assessment_id: str = "test-ass-1",
    targets: list[str] | None = None,
    ports: str = "22,80,443",
    assets: list[SnapshotAsset] | None = None,
    findings: list[SnapshotFinding] | None = None,
    risk_score: float = 25.0,
    risk_level: str = "low",
    p1_p5: dict[str, int] | None = None,
    coverage_metrics: dict | None = None,
) -> AssessmentSnapshot:
    """Helper to build calibrated AssessmentSnapshot instances for testing."""
    if targets is None:
        targets = ["192.168.1.10"]
    if assets is None:
        assets = []
    if findings is None:
        findings = []
    if p1_p5 is None:
        p1_p5 = {"P1": 0, "P2": 0, "P3": 1, "P4": 0, "P5": 0}

    return AssessmentSnapshot(
        schema_version="1.1.0",
        exported_at=datetime.now(UTC),
        assessment=SnapshotAssessment(
            id=assessment_id,
            name=f"Assessment {assessment_id}",
            scope_config={"allowed_targets": targets, "allowed_ports": ports},
            scanner_version="0.7.0",
            status="completed",
            start_time=datetime(2026, 11, 1, 10, 0, tzinfo=UTC),
            end_time=datetime(2026, 11, 1, 10, 5, tzinfo=UTC),
            coverage_metrics=coverage_metrics
            or {
                "targets_assessed": len(targets),
                "unreachable_count": 0,
                "timeout_count": 0,
            },
            risk_score=risk_score,
        ),
        assets=assets,
        findings=findings,
        risk_posture={
            "assessment_id": assessment_id,
            "overall_score": risk_score,
            "risk_level": risk_level,
            "priority_breakdown": p1_p5,
        },
    )


def test_identical_assessments_diff():
    """Diffing identical assessments produces zero deltas and STABLE risk."""
    differencer = AssessmentDifferencer()

    asset = SnapshotAsset(
        ip_address="192.168.1.10",
        observed_hostnames=["web.lab"],
        criticality="high",
        services=[
            SnapshotService(
                port=80,
                protocol="tcp",
                service_name="http",
                product="nginx",
                version="1.24.0",
                confidence="high",
            )
        ],
    )
    snap1 = _make_snapshot(assessment_id="base-1", assets=[asset])
    snap2 = _make_snapshot(assessment_id="target-1", assets=[asset])

    diff = differencer.diff_snapshots(snap1, snap2)

    assert diff.coverage.overlap_type == ScopeOverlapType.IDENTICAL
    assert diff.coverage.is_coverage_complete is True
    assert len(diff.added_hosts) == 0
    assert len(diff.removed_hosts) == 0
    assert diff.retained_hosts_count == 1
    assert len(diff.opened_ports) == 0
    assert len(diff.closed_ports) == 0
    assert len(diff.uncertain_ports) == 0
    assert len(diff.modified_services) == 0
    assert diff.risk.direction == RiskDirection.STABLE
    assert diff.risk.score_delta == 0.0


def test_host_addition_and_removal():
    """Detect added hosts and removed hosts with certainty distinction."""
    differencer = AssessmentDifferencer()

    host_a = SnapshotAsset(ip_address="192.168.1.10", observed_hostnames=["srv-a.lab"])
    host_b = SnapshotAsset(ip_address="192.168.1.20", observed_hostnames=["srv-b.lab"])
    host_c = SnapshotAsset(ip_address="192.168.1.30", observed_hostnames=["srv-c.lab"])

    # Base has A and B
    base = _make_snapshot(
        assessment_id="base-host",
        targets=["192.168.1.10", "192.168.1.20"],
        assets=[host_a, host_b],
    )
    # Target has B and C
    target = _make_snapshot(
        assessment_id="target-host",
        targets=["192.168.1.10", "192.168.1.20", "192.168.1.30"],
        assets=[host_b, host_c],
    )

    diff = differencer.diff_snapshots(base, target)

    assert len(diff.added_hosts) == 1
    assert diff.added_hosts[0].ip_address == "192.168.1.30"
    assert diff.added_hosts[0].certainty == ChangeCertainty.DEFINITIVE

    assert len(diff.removed_hosts) == 1
    assert diff.removed_hosts[0].ip_address == "192.168.1.10"
    assert diff.removed_hosts[0].certainty == ChangeCertainty.DEFINITIVE
    assert diff.retained_hosts_count == 1


def test_port_opened_closed_and_uncertain():
    """Detect opened ports, closed ports, and coverage-uncertain ports."""
    differencer = AssessmentDifferencer()

    # Base: 192.168.1.10 with port 22 and port 80 open (ports 22,80,443 scanned)
    svc22 = SnapshotService(port=22, service_name="ssh", product="OpenSSH", version="8.9p1")
    svc80 = SnapshotService(port=80, service_name="http", product="Apache", version="2.4.52")
    asset_base = SnapshotAsset(ip_address="192.168.1.10", services=[svc22, svc80])

    # Target: port 22 is closed (not in services, but port 22 WAS in target scan ports)
    # port 443 is newly opened
    svc443 = SnapshotService(port=443, service_name="https", product="nginx", version="1.24.0")
    asset_target = SnapshotAsset(ip_address="192.168.1.10", services=[svc80, svc443])

    base = _make_snapshot(
        assessment_id="base-p",
        targets=["192.168.1.10"],
        ports="22,80,443",
        assets=[asset_base],
    )
    target = _make_snapshot(
        assessment_id="target-p",
        targets=["192.168.1.10"],
        ports="22,80,443",
        assets=[asset_target],
    )

    diff = differencer.diff_snapshots(base, target)

    # 443 opened
    assert len(diff.opened_ports) == 1
    assert diff.opened_ports[0].port == 443
    assert diff.opened_ports[0].certainty == ChangeCertainty.DEFINITIVE

    # 22 closed
    assert len(diff.closed_ports) == 1
    assert diff.closed_ports[0].port == 22
    assert diff.closed_ports[0].certainty == ChangeCertainty.DEFINITIVE

    assert len(diff.uncertain_ports) == 0


def test_coverage_uncertain_port_exclusion():
    """Ports absent in target because they were excluded from target scan must be UNCERTAIN_SCOPE_MISMATCH."""
    differencer = AssessmentDifferencer()

    # Base scanned ports 22, 80, 443. Both 22 and 80 were open.
    svc22 = SnapshotService(port=22, service_name="ssh")
    svc80 = SnapshotService(port=80, service_name="http")
    asset_base = SnapshotAsset(ip_address="192.168.1.10", services=[svc22, svc80])

    # Target ONLY scanned port 80! (port 22 was omitted from scan config)
    asset_target = SnapshotAsset(ip_address="192.168.1.10", services=[svc80])

    base = _make_snapshot(
        assessment_id="base-omit",
        targets=["192.168.1.10"],
        ports="22,80,443",
        assets=[asset_base],
    )
    target = _make_snapshot(
        assessment_id="target-omit",
        targets=["192.168.1.10"],
        ports="80",  # port 22 not probed!
        assets=[asset_target],
    )

    diff = differencer.diff_snapshots(base, target)

    # Port 22 MUST NOT be reported as closed! It must be reported as uncertain.
    assert len(diff.closed_ports) == 0
    assert len(diff.uncertain_ports) == 1
    assert diff.uncertain_ports[0].port == 22
    assert diff.uncertain_ports[0].certainty == ChangeCertainty.UNCERTAIN_SCOPE_MISMATCH


def test_service_upgrade_and_reclassification():
    """Detect software version upgrades vs service reclassifications."""
    differencer = AssessmentDifferencer()

    # Base: Apache 2.4.49 on port 80, unknown service on port 8080
    s80_base = SnapshotService(
        port=80,
        service_name="http",
        product="Apache httpd",
        version="2.4.49",
        confidence="high",
    )
    s8080_base = SnapshotService(
        port=8080,
        service_name="unknown",
        product=None,
        version=None,
        confidence="unknown",
    )
    asset_base = SnapshotAsset(ip_address="192.168.1.10", services=[s80_base, s8080_base])

    # Target: Apache 2.4.51 on port 80 (upgrade!), Jenkins 2.401 on port 8080 (reclassification)
    s80_target = SnapshotService(
        port=80,
        service_name="http",
        product="Apache httpd",
        version="2.4.51",
        confidence="high",
    )
    s8080_target = SnapshotService(
        port=8080,
        service_name="http",
        product="Jenkins",
        version="2.401",
        confidence="high",
    )
    asset_target = SnapshotAsset(ip_address="192.168.1.10", services=[s80_target, s8080_target])

    base = _make_snapshot(assessment_id="base-svc", assets=[asset_base])
    target = _make_snapshot(assessment_id="target-svc", assets=[asset_target])

    diff = differencer.diff_snapshots(base, target)

    assert len(diff.modified_services) == 2

    # Find port 80 mod
    mod_80 = next(m for m in diff.modified_services if m.port == 80)
    assert mod_80.is_upgrade is True
    assert mod_80.old_version == "2.4.49"
    assert mod_80.new_version == "2.4.51"

    # Find port 8080 mod
    mod_8080 = next(m for m in diff.modified_services if m.port == 8080)
    assert mod_8080.is_upgrade is False
    assert mod_8080.old_confidence == "unknown"
    assert mod_8080.new_confidence == "high"


def test_finding_state_transitions():
    """Detect new, resolved, persisting, and regressed findings."""
    differencer = AssessmentDifferencer()

    f_persisting = SnapshotFinding(
        id="find-1",
        rule_id="EXPOSE-SSH-PASSWORD-AUTH",
        title="SSH Password Authentication Enabled",
        severity="medium",
        priority="P3",
        state="confirmed",
        target_ip="192.168.1.10",
        port=22,
    )
    f_resolved = SnapshotFinding(
        id="find-2",
        rule_id="EXPOSE-TELNET-CLEAR-TEXT",
        title="Telnet Cleartext Service Detected",
        severity="high",
        priority="P2",
        state="confirmed",
        target_ip="192.168.1.10",
        port=23,
    )
    f_new = SnapshotFinding(
        id="find-3",
        rule_id="EXPOSE-REDIS-UNAUTHENTICATED",
        title="Unauthenticated Redis Cache Server",
        severity="critical",
        priority="P1",
        state="confirmed",
        target_ip="192.168.1.10",
        port=6379,
    )

    base = _make_snapshot(
        assessment_id="base-f",
        ports="22,23,6379",
        findings=[f_persisting, f_resolved],
    )
    target = _make_snapshot(
        assessment_id="target-f",
        ports="22,23,6379",
        findings=[f_persisting, f_new],
    )

    diff = differencer.diff_snapshots(base, target)

    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].rule_id == "EXPOSE-REDIS-UNAUTHENTICATED"

    assert len(diff.resolved_findings) == 1
    assert diff.resolved_findings[0].rule_id == "EXPOSE-TELNET-CLEAR-TEXT"

    assert len(diff.persisting_findings) == 1
    assert diff.persisting_findings[0].rule_id == "EXPOSE-SSH-PASSWORD-AUTH"


def test_risk_delta_and_direction():
    """Verify numerical risk delta, direction classification, and priority shifts."""
    differencer = AssessmentDifferencer()

    # Base has higher risk (70.0, high) with 1 P1 and 2 P2s
    base = _make_snapshot(
        assessment_id="base-r",
        risk_score=70.0,
        risk_level="high",
        p1_p5={"P1": 1, "P2": 2, "P3": 0, "P4": 0, "P5": 0},
    )
    # Target has lower risk (25.0, low) with 0 P1 and 0 P2
    target = _make_snapshot(
        assessment_id="target-r",
        risk_score=25.0,
        risk_level="low",
        p1_p5={"P1": 0, "P2": 0, "P3": 1, "P4": 0, "P5": 0},
    )

    diff = differencer.diff_snapshots(base, target)

    assert diff.risk.base_score == 70.0
    assert diff.risk.target_score == 25.0
    assert diff.risk.score_delta == -45.0
    assert diff.risk.direction == RiskDirection.IMPROVED
    assert diff.risk.priority_changes["P1"] == -1
    assert diff.risk.priority_changes["P2"] == -2
    assert diff.risk.priority_changes["P3"] == 1


def test_scope_overlap_types():
    """Verify boundary overlap classification across various target combinations."""
    differencer = AssessmentDifferencer()

    # SUPERSET: target adds targets
    s_base = _make_snapshot(targets=["192.168.1.10"])
    s_superset = _make_snapshot(targets=["192.168.1.10", "192.168.1.20"])
    diff_superset = differencer.diff_snapshots(s_base, s_superset)
    assert diff_superset.coverage.overlap_type == ScopeOverlapType.SUPERSET

    # SUBSET: target removes targets
    diff_subset = differencer.diff_snapshots(s_superset, s_base)
    assert diff_subset.coverage.overlap_type == ScopeOverlapType.SUBSET

    # PARTIAL_OVERLAP: some in common, some different
    s_other = _make_snapshot(targets=["192.168.1.20", "192.168.1.30"])
    diff_partial = differencer.diff_snapshots(s_superset, s_other)
    assert diff_partial.coverage.overlap_type == ScopeOverlapType.PARTIAL_OVERLAP

    # DISJOINT: zero overlap
    s_disjoint = _make_snapshot(targets=["10.0.0.1"])
    diff_disjoint = differencer.diff_snapshots(s_base, s_disjoint)
    assert diff_disjoint.coverage.overlap_type == ScopeOverlapType.DISJOINT
    assert diff_disjoint.coverage.is_coverage_complete is False


def test_executive_narrative_generation():
    """Verify executive human summary narrative includes all major shifts."""
    differencer = AssessmentDifferencer()

    host_new = SnapshotAsset(ip_address="192.168.1.50")
    svc_new = SnapshotService(port=8080, service_name="http")
    host_new.services = [svc_new]

    base = _make_snapshot(assessment_id="base-narrative", risk_score=50.0, risk_level="medium")
    target = _make_snapshot(
        assessment_id="target-narrative",
        targets=["192.168.1.10", "192.168.1.50"],
        assets=[host_new],
        risk_score=75.0,
        risk_level="high",
        findings=[
            SnapshotFinding(
                rule_id="EXPOSE-DEV-PORT",
                title="Exposed Development Port",
                severity="high",
                priority="P2",
                target_ip="192.168.1.50",
                port=8080,
            )
        ],
    )

    diff = differencer.diff_snapshots(base, target)
    narrative = diff.summary_narrative

    assert any("Attack-Surface Risk" in bullet or "DEGRADED" in bullet for bullet in narrative)
    assert any("Host Inventory" in bullet for bullet in narrative)
    assert any("Network Perimeter" in bullet for bullet in narrative)
    assert any("Security Exposures" in bullet for bullet in narrative)
