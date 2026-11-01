"""Unit tests for report generation (HTML, JSON, Markdown, CSV) and snapshot export/import."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, FindingRecord, ServiceRecord


@pytest.fixture
def reports_snapshots_setup(tmp_path):
    db_file = tmp_path / "test_reports_snaps.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)
    db = DatabaseManager(db_url=f"sqlite:///{db_file}")
    db.init_db()
    repo = AssetRepository(db)

    now = datetime.now(UTC)
    with db.session() as session:
        a = AssessmentRecord(
            id="test-rep-assess-1",
            name="Report Assessment",
            scanner_version="0.8.0",
            status="completed",
            scope_config={"allowed_targets": ["10.0.0.5"], "allowed_ports": "80"},
            coverage_metrics={
                "observed_services": [
                    {
                        "ip_address": "10.0.0.5",
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
        session.add(a)

        asset = AssetRecord(
            id="test-rep-asset-1",
            ip_address="10.0.0.5",
            address_family="ipv4",
            observed_hostnames=["demo.local"],
            criticality="high",
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(asset)

        svc = ServiceRecord(
            id="test-rep-svc-1",
            asset_id="test-rep-asset-1",
            port=80,
            protocol="tcp",
            service_name="http",
            confidence="high",
            first_observed_at=now,
            last_observed_at=now,
        )
        session.add(svc)

        finding = FindingRecord(
            id="test-rep-finding-1",
            assessment_id="test-rep-assess-1",
            asset_id="test-rep-asset-1",
            service_id="test-rep-svc-1",
            rule_id="RULE-CLEARTEXT",
            title="Unencrypted HTTP Service",
            description="Cleartext HTTP transport detected",
            severity="medium",
            priority="P3",
            state="confirmed",
            created_at=now,
            updated_at=now,
        )
        session.add(finding)

    with TestClient(app) as client:
        yield client, repo, db


def test_generate_report_all_formats(reports_snapshots_setup):
    """Verify report generation across all supported formats (HTML, JSON, Markdown, CSV)."""
    client, repo, db = reports_snapshots_setup
    assess_id = "test-rep-assess-1"

    # HTML
    res_html = client.get(f"/api/v1/reports/{assess_id}?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "<!DOCTYPE html>" in res_html.text

    # JSON
    res_json = client.get(f"/api/v1/reports/{assess_id}?format=json")
    assert res_json.status_code == 200
    assert "application/json" in res_json.headers["content-type"]
    data = res_json.json()
    assert data["metadata"]["assessment_id"] == assess_id

    # Markdown
    res_md = client.get(f"/api/v1/reports/{assess_id}?format=markdown")
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]
    assert "# ReconForge Attack-Surface Exposure" in res_md.text

    # CSV
    res_csv = client.get(f"/api/v1/reports/{assess_id}?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "Priority,Severity,Title,Rule ID" in res_csv.text

    # Invalid format -> 400
    res_invalid = client.get(f"/api/v1/reports/{assess_id}?format=pdf")
    assert res_invalid.status_code == 400
    assert "Unsupported report format" in res_invalid.json()["detail"]


def test_snapshot_export_and_import(reports_snapshots_setup):
    """Verify snapshot export produces valid JSON and import persists data."""
    client, repo, db = reports_snapshots_setup
    assess_id = "test-rep-assess-1"

    # 1. Export snapshot
    export_res = client.get(f"/api/v1/snapshots/export/{assess_id}")
    assert export_res.status_code == 200
    assert "attachment" in export_res.headers.get("content-disposition", "")
    snap_data = export_res.json()
    assert snap_data["schema_version"] in ("1.0.0", "1.1.0")
    assert snap_data["assessment"]["id"] == assess_id
    assert len(snap_data["assets"]) >= 1

    # 2. Modify snapshot ID and re-import
    snap_data["assessment"]["id"] = "imported-assessment-99"
    snap_data["assessment"]["name"] = "Imported Security Assessment"
    import_res = client.post("/api/v1/snapshots/import", json=snap_data)
    assert import_res.status_code == 200
    import_body = import_res.json()
    assert import_body["imported_assessment_id"] == "imported-assessment-99"
    assert import_body["assessment_name"] == "Imported Security Assessment"
    assert import_body["assets_count"] >= 1

    # 3. Verify imported assessment exists in repository
    detail_res = client.get("/api/v1/assessments/imported-assessment-99")
    assert detail_res.status_code == 200
    assert detail_res.json()["name"] == "Imported Security Assessment"
