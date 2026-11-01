"""Unit tests for attack-surface scoring breakdown and assessment differencing endpoints."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import (
    AssessmentSnapshot,
    SnapshotAssessment,
    SnapshotAsset,
    SnapshotService,
)
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, FindingRecord, ServiceRecord


@pytest.fixture
def scoring_diff_setup(tmp_path):
    db_file = tmp_path / "test_scoring_diff.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)
    db = DatabaseManager(db_url=f"sqlite:///{db_file}")
    db.init_db()
    repo = AssetRepository(db)

    now = datetime.now(UTC)
    with db.session() as session:
        # Assessment 1 (Base)
        a1 = AssessmentRecord(
            id="assess-base",
            name="Base Assessment",
            scanner_version="0.8.0",
            status="completed",
            scope_config={"allowed_targets": ["192.168.1.10"], "allowed_ports": "80,443"},
            coverage_metrics={
                "observed_services": [
                    {
                        "target_ip": "192.168.1.10",
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service_name": "http",
                    }
                ]
            },
            start_time=now,
            end_time=now,
        )
        session.add(a1)

        # Assessment 2 (Target)
        a2 = AssessmentRecord(
            id="assess-target",
            name="Target Assessment",
            scanner_version="0.8.0",
            status="completed",
            scope_config={"allowed_targets": ["192.168.1.10"], "allowed_ports": "80,443,8080"},
            coverage_metrics={
                "observed_services": [
                    {
                        "target_ip": "192.168.1.10",
                        "port": 80,
                        "protocol": "tcp",
                        "state": "closed",
                        "service_name": "http",
                    },
                    {
                        "target_ip": "192.168.1.10",
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service_name": "https",
                    },
                ]
            },
            start_time=now,
            end_time=now,
        )
        session.add(a2)

        # Asset
        asset = AssetRecord(
            id="asset-1",
            ip_address="192.168.1.10",
            address_family="ipv4",
            observed_hostnames=["host1.lab"],
            criticality="critical",
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(asset)

        # Service
        svc = ServiceRecord(
            id="svc-1",
            asset_id="asset-1",
            port=80,
            protocol="tcp",
            service_name="http",
            confidence="high",
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(svc)

        # Finding on base assessment
        f = FindingRecord(
            id="finding-1",
            assessment_id="assess-base",
            asset_id="asset-1",
            service_id="svc-1",
            rule_id="RULE-CLEARTEXT",
            title="Cleartext HTTP Exposure",
            description="HTTP is unencrypted",
            severity="medium",
            priority="P3",
            state="confirmed",
            created_at=now,
            updated_at=now,
        )
        session.add(f)

    with TestClient(app) as client:
        yield client, repo, db


def test_scoring_endpoints(scoring_diff_setup):
    """Verify estate posture and individual asset score breakdown routes."""
    client, repo, db = scoring_diff_setup

    # 1. Assessment posture
    res_posture = client.get("/api/v1/scoring/assess-base")
    assert res_posture.status_code == 200
    posture = res_posture.json()
    assert posture["assessment_id"] == "assess-base"
    assert posture["risk_score"] >= 0.0
    assert "priority_distribution" in posture
    assert len(posture["asset_scores"]) >= 1

    # 2. Asset score breakdown
    res_asset = client.get("/api/v1/scoring/assess-base/assets/asset-1")
    assert res_asset.status_code == 200
    asset_score = res_asset.json()
    assert asset_score["asset_id"] == "asset-1"
    assert asset_score["criticality"] == "critical"
    assert asset_score["criticality_multiplier"] == 1.5
    assert len(asset_score["component_explanations"]) >= 1


def test_diff_by_assessment_ids(scoring_diff_setup):
    """Verify differencing endpoint computes host/port/risk deltas between two IDs."""
    client, repo, db = scoring_diff_setup

    payload = {"base_id": "assess-base", "target_id": "assess-target"}
    res = client.post("/api/v1/diff", json=payload)
    assert res.status_code == 200
    diff = res.json()
    assert diff["base_assessment_id"] == "assess-base"
    assert diff["target_assessment_id"] == "assess-target"
    assert "coverage" in diff
    assert "risk" in diff
    assert len(diff["closed_ports"]) == 1
    assert diff["closed_ports"][0]["port"] == 80


def test_diff_by_snapshots(scoring_diff_setup):
    """Verify offline snapshot differencing endpoint."""
    client, repo, db = scoring_diff_setup

    now = datetime.now(UTC)
    s1 = AssessmentSnapshot(
        schema_version="1.1.0",
        assessment=SnapshotAssessment(
            id="snap-1",
            name="Snapshot One",
            scanner_version="0.8.0",
            scope_config={"allowed_targets": ["10.0.0.1"], "allowed_ports": "80"},
            coverage_metrics={"configured_targets": ["10.0.0.1"]},
            start_time=now,
            end_time=now,
        ),
        assets=[
            SnapshotAsset(
                ip_address="10.0.0.1",
                services=[SnapshotService(port=80, service_name="http")],
            )
        ],
    )
    s2 = AssessmentSnapshot(
        schema_version="1.1.0",
        assessment=SnapshotAssessment(
            id="snap-2",
            name="Snapshot Two",
            scanner_version="0.8.0",
            scope_config={"allowed_targets": ["10.0.0.1"], "allowed_ports": "80,443"},
            coverage_metrics={"configured_targets": ["10.0.0.1"]},
            start_time=now,
            end_time=now,
        ),
        assets=[
            SnapshotAsset(
                ip_address="10.0.0.1",
                services=[
                    SnapshotService(port=80, service_name="http"),
                    SnapshotService(port=443, service_name="https"),
                ],
            )
        ],
    )

    payload = {
        "base_snapshot": s1.model_dump(mode="json"),
        "target_snapshot": s2.model_dump(mode="json"),
    }
    res = client.post("/api/v1/diff/snapshots", json=payload)
    assert res.status_code == 200
    diff = res.json()
    assert len(diff["opened_ports"]) == 1
    assert diff["opened_ports"][0]["port"] == 443
