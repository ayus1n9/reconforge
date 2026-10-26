"""Unit tests for assessment snapshot export, import, and round-trip consistency."""

import pytest

from reconforge.core.enums import ObservationConfidence, PortState, ScanStatus
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import AssessmentSnapshot, SnapshotManager
from reconforge.storage.database import DatabaseManager


@pytest.fixture
def populated_repo() -> tuple[AssetRepository, SnapshotManager, str]:
    db = DatabaseManager("sqlite:///:memory:")
    repo = AssetRepository(db)
    manager = SnapshotManager(db)

    scan_id = "test-export-uuid"
    obs = [
        PortObservation(
            target_ip="192.168.1.1",
            hostname="gateway.local",
            port=443,
            state=PortState.OPEN,
            service=ServiceFingerprint(
                service_name="https",
                product="lighttpd",
                version="1.4.69",
                confidence=ObservationConfidence.HIGH,
            ),
        )
    ]
    summary = ScanSummary(
        scan_id=scan_id,
        targets_assessed=1,
        probes_attempted=1,
        open_count=1,
        closed_count=0,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.05,
        status=ScanStatus.COMPLETED,
    )
    repo.record_scan_results(
        assessment_id=scan_id,
        scope_config={"targets": ["192.168.1.1"]},
        scanner_version="0.3.0",
        observations=obs,
        summary=summary,
        assessment_name="Gateway Audit",
    )
    return repo, manager, scan_id


def test_snapshot_export_schema(populated_repo):
    repo, manager, scan_id = populated_repo
    json_str = manager.export_snapshot(scan_id)

    # Validate JSON parses and adheres to AssessmentSnapshot model
    snapshot = AssessmentSnapshot.model_validate_json(json_str)
    assert snapshot.schema_version == "1.0.0"
    assert snapshot.assessment.id == scan_id
    assert snapshot.assessment.name == "Gateway Audit"
    assert len(snapshot.assets) >= 1

    gateway_asset = next(a for a in snapshot.assets if a.ip_address == "192.168.1.1")
    assert "gateway.local" in gateway_asset.observed_hostnames
    assert len(gateway_asset.services) == 1
    assert gateway_asset.services[0].port == 443
    assert gateway_asset.services[0].product == "lighttpd"


def test_snapshot_import_roundtrip(populated_repo):
    repo, manager, scan_id = populated_repo
    exported_json = manager.export_snapshot(scan_id)

    # Import into a completely fresh, empty in-memory database
    target_db = DatabaseManager("sqlite:///:memory:")
    target_repo = AssetRepository(target_db)
    target_manager = SnapshotManager(target_db)

    imported_assessment = target_manager.import_snapshot(exported_json)
    assert imported_assessment.id == scan_id
    assert imported_assessment.name == "Gateway Audit"

    # Verify inventory was reconstructed
    asset = target_repo.get_asset("192.168.1.1")
    assert asset is not None
    assert "gateway.local" in asset.observed_hostnames
    assert len(asset.services) == 1
    assert asset.services[0].port == 443
    assert asset.services[0].product == "lighttpd"
    assert asset.services[0].version == "1.4.69"
