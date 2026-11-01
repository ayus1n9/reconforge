"""Unit tests for asset inventory querying and finding lifecycle management."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, FindingRecord, ServiceRecord


@pytest.fixture
def asset_finding_setup(tmp_path):
    db_file = tmp_path / "test_assets_findings.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)
    db = DatabaseManager(db_url=f"sqlite:///{db_file}")
    db.init_db()
    repo = AssetRepository(db)

    # Seed data
    now = datetime.now(UTC)
    with db.session() as session:
        assessment = AssessmentRecord(
            id="test-assess-1",
            name="Seed Assessment",
            scanner_version="0.8.0",
            status="completed",
            start_time=now,
            end_time=now,
        )
        session.add(assessment)

        asset1 = AssetRecord(
            id="test-asset-1",
            ip_address="10.10.10.5",
            address_family="ipv4",
            observed_hostnames=["web.lab.local"],
            criticality="high",
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(asset1)

        service1 = ServiceRecord(
            id="test-service-1",
            asset_id="test-asset-1",
            port=443,
            protocol="tcp",
            service_name="https",
            product="nginx",
            version="1.24.0",
            confidence="high",
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(service1)

        finding1 = FindingRecord(
            id="test-finding-1",
            assessment_id="test-assess-1",
            asset_id="test-asset-1",
            service_id="test-service-1",
            rule_id="RULE-TLS-OLD",
            title="Deprecated TLS Version",
            description="TLS 1.0/1.1 enabled on port 443",
            severity="high",
            priority="P2",
            state="potential_exposure",
            evidence={"protocol": "TLSv1.0"},
            remediation_guidance="Disable TLS 1.0 and 1.1",
            created_at=now,
            updated_at=now,
        )
        session.add(finding1)

    with TestClient(app) as client:
        yield client, repo, db


def test_list_and_get_assets(asset_finding_setup):
    """Verify asset inventory query and filtering."""
    client, repo, db = asset_finding_setup

    # List all assets
    res = client.get("/api/v1/assets")
    assert res.status_code == 200
    assets = res.json()
    assert len(assets) == 1
    assert assets[0]["ip_address"] == "10.10.10.5"
    assert assets[0]["criticality"] == "high"

    # Filter by criticality match
    res_high = client.get("/api/v1/assets?criticality=high")
    assert res_high.status_code == 200
    assert len(res_high.json()) == 1

    # Filter by criticality mismatch
    res_low = client.get("/api/v1/assets?criticality=low")
    assert res_low.status_code == 200
    assert len(res_low.json()) == 0

    # Get asset detail by IP
    res_detail = client.get("/api/v1/assets/10.10.10.5")
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["ip_address"] == "10.10.10.5"
    assert len(detail["services"]) == 1
    assert detail["services"][0]["port"] == 443

    # Get asset detail by non-existent IP -> 404
    res_404 = client.get("/api/v1/assets/10.99.99.99")
    assert res_404.status_code == 404


def test_list_and_patch_findings(asset_finding_setup):
    """Verify finding queries and state mutation lifecycle."""
    client, repo, db = asset_finding_setup

    # List findings
    res = client.get("/api/v1/findings")
    assert res.status_code == 200
    findings = res.json()
    assert len(findings) == 1
    assert findings[0]["id"] == "test-finding-1"
    assert findings[0]["severity"] == "high"
    assert findings[0]["priority"] == "P2"

    # Filter by severity
    res_sev = client.get("/api/v1/findings?severity=high")
    assert len(res_sev.json()) == 1
    res_crit = client.get("/api/v1/findings?severity=critical")
    assert len(res_crit.json()) == 0

    # Get finding detail
    res_f = client.get("/api/v1/findings/test-finding-1")
    assert res_f.status_code == 200
    f_detail = res_f.json()
    assert f_detail["title"] == "Deprecated TLS Version"
    assert f_detail["state"] == "potential_exposure"

    # Patch finding state with valid state and audit reason
    patch_payload = {
        "state": "accepted_risk",
        "reason": "Business exception approved until Q3 infrastructure migration.",
    }
    patch_res = client.patch("/api/v1/findings/test-finding-1/state", json=patch_payload)
    assert patch_res.status_code == 200
    updated = patch_res.json()
    assert updated["state"] == "accepted_risk"
    assert "state_history" in updated["evidence"]
    assert updated["evidence"]["state_history"][-1]["reason"] == patch_payload["reason"]

    # Patch with invalid state -> 400
    bad_patch = client.patch(
        "/api/v1/findings/test-finding-1/state", json={"state": "not_a_valid_state"}
    )
    assert bad_patch.status_code == 400
    assert "Invalid finding state" in bad_patch.json()["detail"]

    # Patch non-existent finding -> 404
    not_found_patch = client.patch(
        "/api/v1/findings/nonexistent-id/state", json={"state": "false_positive"}
    )
    assert not_found_patch.status_code == 404
