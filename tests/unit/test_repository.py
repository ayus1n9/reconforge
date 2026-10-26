"""Unit tests for AssetRepository and relational data modeling."""

import pytest

from reconforge.core.enums import ObservationConfidence, PortState, ScanStatus
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager


@pytest.fixture
def memory_repo() -> AssetRepository:
    """Fixture providing an isolated in-memory AssetRepository."""
    db = DatabaseManager("sqlite:///:memory:")
    return AssetRepository(db)


def test_asset_identity_separation_and_hostnames(memory_repo: AssetRepository):
    # Two distinct IP addresses sharing the same hostname
    asset1 = memory_repo.upsert_asset(
        ip_address="10.0.0.1",
        hostname="cluster.internal",
        source="scanner",
    )
    asset2 = memory_repo.upsert_asset(
        ip_address="10.0.0.2",
        hostname="cluster.internal",
        source="scanner",
    )

    # Assets MUST remain separate entities
    assert asset1.id != asset2.id
    assert asset1.ip_address == "10.0.0.1"
    assert asset2.ip_address == "10.0.0.2"
    assert "cluster.internal" in asset1.observed_hostnames
    assert "cluster.internal" in asset2.observed_hostnames

    # Adding a second hostname to asset1
    updated_asset1 = memory_repo.upsert_asset(
        ip_address="10.0.0.1",
        hostname="web1.internal",
    )
    assert set(updated_asset1.observed_hostnames) == {"cluster.internal", "web1.internal"}


def test_asset_timestamp_monotonicity(memory_repo: AssetRepository):
    asset = memory_repo.upsert_asset(ip_address="192.168.1.50")
    first_seen = asset.first_observed_at

    # Second observation
    asset_updated = memory_repo.upsert_asset(ip_address="192.168.1.50")
    assert asset_updated.first_observed_at == first_seen
    assert asset_updated.last_observed_at >= first_seen


def test_service_upsert_and_confidence_elevation(memory_repo: AssetRepository):
    asset = memory_repo.upsert_asset(ip_address="172.16.0.10")

    # Initial probe: port open, unknown service
    srv1 = memory_repo.upsert_service(
        asset_id=asset.id,
        port=80,
        protocol="tcp",
        service_name="unknown",
        confidence="unknown",
    )
    assert srv1.service_name == "unknown"

    # Subsequent probe: identified as nginx 1.24
    srv2 = memory_repo.upsert_service(
        asset_id=asset.id,
        port=80,
        protocol="tcp",
        service_name="http",
        product="nginx",
        version="1.24.0",
        confidence="high",
        banner_snippet="nginx/1.24.0",
    )
    assert srv2.id == srv1.id  # Same unique service record
    assert srv2.service_name == "http"
    assert srv2.product == "nginx"
    assert srv2.version == "1.24.0"
    assert srv2.confidence == "high"


def test_record_scan_results_atomic(memory_repo: AssetRepository):
    observations = [
        PortObservation(
            target_ip="10.10.10.5",
            hostname="db.internal",
            port=5432,
            state=PortState.OPEN,
            response_time_ms=1.2,
            service=ServiceFingerprint(
                service_name="postgresql",
                product="PostgreSQL",
                confidence=ObservationConfidence.HIGH,
                banner_snippet="PostgreSQL (SSL Supported: True)",
            ),
        ),
        PortObservation(
            target_ip="10.10.10.5",
            hostname="db.internal",
            port=80,
            state=PortState.CLOSED,
            response_time_ms=0.5,
        ),
    ]

    summary = ScanSummary(
        scan_id="test-scan-uuid-1",
        targets_assessed=1,
        probes_attempted=2,
        open_count=1,
        closed_count=1,
        filtered_count=0,
        timeout_count=0,
        unreachable_count=0,
        error_count=0,
        duration_seconds=0.1,
        status=ScanStatus.COMPLETED,
    )

    assessment = memory_repo.record_scan_results(
        assessment_id="test-scan-uuid-1",
        scope_config={"targets": ["10.10.10.5"]},
        scanner_version="0.3.0",
        observations=observations,
        summary=summary,
    )

    assert assessment.id == "test-scan-uuid-1"
    assert assessment.status == "completed"

    # Verify asset was created
    asset = memory_repo.get_asset("10.10.10.5")
    assert asset is not None
    assert "db.internal" in asset.observed_hostnames
    assert len(asset.services) == 1
    assert asset.services[0].port == 5432
    assert asset.services[0].service_name == "postgresql"
