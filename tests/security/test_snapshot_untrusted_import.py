"""Security tests: Untrusted snapshot import validation and injection resistance."""

import pytest

from reconforge.core.exceptions import ConfigurationError
from reconforge.inventory.snapshot import SnapshotManager
from reconforge.storage.database import DatabaseManager


@pytest.fixture
def snapshot_manager() -> SnapshotManager:
    db = DatabaseManager("sqlite:///:memory:")
    return SnapshotManager(db)


def test_reject_malformed_json(snapshot_manager: SnapshotManager):
    with pytest.raises(ConfigurationError, match="Malformed snapshot JSON"):
        snapshot_manager.import_snapshot("NOT_VALID_JSON{")


def test_reject_unsupported_schema_version(snapshot_manager: SnapshotManager):
    payload = {
        "schema_version": "99.0.0",
        "assessment": {"id": "1", "name": "Fake"},
    }
    with pytest.raises(ConfigurationError, match="Unsupported snapshot schema version"):
        snapshot_manager.import_snapshot(payload)


def test_reject_sql_injection_in_ip(snapshot_manager: SnapshotManager):
    # Attempting SQL injection via IP address field
    payload = {
        "schema_version": "1.0.0",
        "assessment": {
            "id": "test-ass-1",
            "name": "Injection Test",
        },
        "assets": [
            {
                "ip_address": "10.0.0.1'; DROP TABLE assets; --",
                "services": [],
            }
        ],
    }
    with pytest.raises(ConfigurationError, match="Snapshot validation failed"):
        snapshot_manager.import_snapshot(payload)


def test_reject_out_of_bounds_port(snapshot_manager: SnapshotManager):
    payload = {
        "schema_version": "1.0.0",
        "assessment": {
            "id": "test-ass-2",
            "name": "Port Bounds Test",
        },
        "assets": [
            {
                "ip_address": "10.0.0.1",
                "services": [
                    {
                        "port": 99999,  # Illegal port
                        "service_name": "http",
                    }
                ],
            }
        ],
    }
    with pytest.raises(ConfigurationError, match="Snapshot validation failed"):
        snapshot_manager.import_snapshot(payload)


def test_sanitize_escape_sequences_in_banner(snapshot_manager: SnapshotManager):
    payload = {
        "schema_version": "1.0.0",
        "assessment": {
            "id": "test-ass-3",
            "name": "Sanitization Test",
        },
        "assets": [
            {
                "ip_address": "10.0.0.5",
                "services": [
                    {
                        "port": 80,
                        "service_name": "http",
                        "banner_snippet": "Apache\x1b[31;1mRedText\x1b[0m\x00\r\nHeader",
                    }
                ],
            }
        ],
    }
    assessment = snapshot_manager.import_snapshot(payload)
    assert assessment.id == "test-ass-3"

    with snapshot_manager.db.session() as session:
        from sqlalchemy import select

        from reconforge.storage.models import ServiceRecord

        srv = session.execute(select(ServiceRecord).where(ServiceRecord.port == 80)).scalar_one()
        assert "\x00" not in srv.banner_snippet
        assert "\x1b" not in srv.banner_snippet
        assert "Apache" in srv.banner_snippet
