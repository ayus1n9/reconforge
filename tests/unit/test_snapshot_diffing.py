"""Unit tests for offline snapshot diffing, v1.0.0 schema compatibility, and CLI diff commands."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reconforge.cli import app
from reconforge.core.enums import ObservationConfidence, PortState, ScanStatus
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.diffing.engine import AssessmentDifferencer
from reconforge.diffing.models import ScopeOverlapType
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import AssessmentSnapshot, SnapshotManager
from reconforge.storage.database import DatabaseManager

runner = CliRunner()


@pytest.fixture
def repo_with_two_scans(tmp_path: Path):
    db_file = tmp_path / "test_diff.db"
    db = DatabaseManager(f"sqlite:///{db_file}")
    repo = AssetRepository(db)
    snapshot_mgr = SnapshotManager(db)

    # Scan 1: Baseline (ports 22, 80 open)
    obs_1 = [
        PortObservation(
            target_ip="10.0.0.1",
            port=22,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="ssh",
                product="OpenSSH",
                version="8.2p1",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
        PortObservation(
            target_ip="10.0.0.1",
            port=80,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="http",
                product="Apache",
                version="2.4.41",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
    ]
    summary_1 = ScanSummary(
        scan_id="scan-base-1",
        targets_assessed=1,
        probes_attempted=2,
        open_count=2,
        closed_count=0,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.1,
        status=ScanStatus.COMPLETED,
    )
    repo.record_scan_results(
        assessment_id="scan-base-1",
        scope_config={"allowed_targets": ["10.0.0.1"], "allowed_ports": "22,80,443"},
        scanner_version="0.6.0",
        observations=obs_1,
        summary=summary_1,
        assessment_name="Baseline Audit",
    )

    # Scan 2: Target (port 22 closed, port 80 upgraded to 2.4.52, port 443 opened)
    obs_2 = [
        PortObservation(
            target_ip="10.0.0.1",
            port=80,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="http",
                product="Apache",
                version="2.4.52",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
        PortObservation(
            target_ip="10.0.0.1",
            port=443,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="https",
                product="Apache",
                version="2.4.52",
                confidence=ObservationConfidence.HIGH,
            ),
        ),
    ]
    summary_2 = ScanSummary(
        scan_id="scan-comp-2",
        targets_assessed=1,
        probes_attempted=2,
        open_count=2,
        closed_count=0,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.1,
        status=ScanStatus.COMPLETED,
    )
    repo.record_scan_results(
        assessment_id="scan-comp-2",
        scope_config={"allowed_targets": ["10.0.0.1"], "allowed_ports": "22,80,443"},
        scanner_version="0.7.0",
        observations=obs_2,
        summary=summary_2,
        assessment_name="Comparison Audit",
    )

    return repo, snapshot_mgr, db_file


def test_diff_assessments_repository(repo_with_two_scans):
    """Diff two live assessments from the database repository."""
    repo, _, _ = repo_with_two_scans
    differencer = AssessmentDifferencer()

    diff = differencer.diff_assessments("scan-base-1", "scan-comp-2", repo)

    assert diff.base_assessment_id == "scan-base-1"
    assert diff.target_assessment_id == "scan-comp-2"
    assert diff.coverage.overlap_type == ScopeOverlapType.IDENTICAL

    # Port 443 opened
    assert any(p.port == 443 for p in diff.opened_ports)
    # Port 22 closed
    assert any(p.port == 22 for p in diff.closed_ports)
    # Port 80 upgraded (2.4.41 -> 2.4.52)
    assert any(m.port == 80 and m.is_upgrade for m in diff.modified_services)


def test_diff_snapshots_offline(repo_with_two_scans, tmp_path: Path):
    """Export snapshots to JSON files, reload, and verify identical diff results."""
    repo, snapshot_mgr, _ = repo_with_two_scans
    differencer = AssessmentDifferencer()

    snap1_str = snapshot_mgr.export_snapshot("scan-base-1")
    snap2_str = snapshot_mgr.export_snapshot("scan-comp-2")

    file1 = tmp_path / "base.json"
    file2 = tmp_path / "comp.json"
    file1.write_text(snap1_str, encoding="utf-8")
    file2.write_text(snap2_str, encoding="utf-8")

    snap1 = AssessmentSnapshot.model_validate_json(file1.read_text(encoding="utf-8"))
    snap2 = AssessmentSnapshot.model_validate_json(file2.read_text(encoding="utf-8"))

    diff = differencer.diff_snapshots(snap1, snap2)

    assert diff.base_assessment_id == "scan-base-1"
    assert diff.target_assessment_id == "scan-comp-2"
    assert len(diff.opened_ports) == 1
    assert diff.opened_ports[0].port == 443
    assert len(diff.closed_ports) == 1
    assert diff.closed_ports[0].port == 22


def test_v1_0_0_backward_compatibility(tmp_path: Path):
    """Verify v1.0.0 snapshot schema without findings or posture diffs cleanly."""
    differencer = AssessmentDifferencer()

    # Legacy v1.0.0 JSON without findings or risk_posture fields
    legacy_json = {
        "schema_version": "1.0.0",
        "exported_at": "2026-10-25T10:00:00Z",
        "assessment": {
            "id": "legacy-base-uuid",
            "name": "Legacy Assessment",
            "scope_config": {"allowed_targets": ["10.0.0.1"], "allowed_ports": "80"},
            "scanner_version": "0.3.0",
            "status": "completed",
            "start_time": "2026-10-25T10:00:00Z",
            "coverage_metrics": {"targets_assessed": 1},
        },
        "assets": [
            {
                "id": "asset-1",
                "ip_address": "10.0.0.1",
                "address_family": "ipv4",
                "services": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service_name": "http",
                        "product": "Apache",
                        "version": "2.4.29",
                        "confidence": "high",
                    }
                ],
            }
        ],
    }

    # Modern v1.1.0 JSON
    modern_json = {
        "schema_version": "1.1.0",
        "exported_at": "2026-11-01T10:00:00Z",
        "assessment": {
            "id": "modern-target-uuid",
            "name": "Modern Assessment",
            "scope_config": {"allowed_targets": ["10.0.0.1"], "allowed_ports": "80"},
            "scanner_version": "0.7.0",
            "status": "completed",
            "start_time": "2026-11-01T10:00:00Z",
            "coverage_metrics": {"targets_assessed": 1},
        },
        "assets": [
            {
                "id": "asset-1",
                "ip_address": "10.0.0.1",
                "address_family": "ipv4",
                "services": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service_name": "http",
                        "product": "Apache",
                        "version": "2.4.52",
                        "confidence": "high",
                    }
                ],
            }
        ],
        "findings": [],
        "risk_posture": None,
    }

    snap_base = AssessmentSnapshot.model_validate(legacy_json)
    snap_target = AssessmentSnapshot.model_validate(modern_json)

    diff = differencer.diff_snapshots(snap_base, snap_target)

    assert diff.base_assessment_id == "legacy-base-uuid"
    assert diff.target_assessment_id == "modern-target-uuid"
    assert len(diff.modified_services) == 1
    assert diff.modified_services[0].is_upgrade is True
    assert diff.modified_services[0].old_version == "2.4.29"
    assert diff.modified_services[0].new_version == "2.4.52"


def test_cli_diff_command(repo_with_two_scans):
    """Test CLI diff command with terminal output and --json option."""
    _, _, db_file = repo_with_two_scans

    # 1. Terminal Rich Render
    res_rich = runner.invoke(
        app,
        ["diff", "scan-base-1", "scan-comp-2", "--db-path", str(db_file)],
    )
    assert res_rich.exit_code == 0
    assert "ReconForge Assessment Difference & Change Detection Report" in res_rich.stdout
    assert (
        "Host Inventory Changes" in res_rich.stdout
        or "No host inventory changes" in res_rich.stdout
    )
    assert "Port & Exposure Transport Changes" in res_rich.stdout

    # 2. JSON Render
    res_json = runner.invoke(
        app,
        ["diff", "scan-base-1", "scan-comp-2", "--db-path", str(db_file), "--json"],
    )
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["base_assessment_id"] == "scan-base-1"
    assert parsed["target_assessment_id"] == "scan-comp-2"
    assert "coverage" in parsed
    assert "opened_ports" in parsed
    assert len(parsed["opened_ports"]) == 1
    assert parsed["opened_ports"][0]["port"] == 443


def test_cli_diff_snapshots_command(repo_with_two_scans, tmp_path: Path):
    """Test CLI diff-snapshots command comparing two disk files."""
    repo, snapshot_mgr, _ = repo_with_two_scans

    f1 = tmp_path / "snap1.json"
    f2 = tmp_path / "snap2.json"
    f1.write_text(snapshot_mgr.export_snapshot("scan-base-1"), encoding="utf-8")
    f2.write_text(snapshot_mgr.export_snapshot("scan-comp-2"), encoding="utf-8")

    res = runner.invoke(app, ["diff-snapshots", str(f1), str(f2)])
    assert res.exit_code == 0
    assert "ReconForge Assessment Difference & Change Detection Report" in res.stdout

    # Test via snapshot diff subcommand
    res_sub = runner.invoke(app, ["snapshot", "diff", str(f1), str(f2)])
    assert res_sub.exit_code == 0
    assert "ReconForge Assessment Difference & Change Detection Report" in res_sub.stdout
