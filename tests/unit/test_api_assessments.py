"""Unit tests for assessment launch, listing, detail retrieval, cancellation, and deletion."""

import pytest
from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.database import DatabaseManager


@pytest.fixture
def test_setup(tmp_path):
    db_file = tmp_path / "test_assessments.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)
    db = DatabaseManager(db_url=f"sqlite:///{db_file}")
    db.init_db()
    repo = AssetRepository(db)
    with TestClient(app) as client:
        yield client, repo, db


def test_assessment_crud_flow(test_setup):
    """Verify assessment launch, list, detail, cancellation, and deletion endpoints."""
    client, repo, db = test_setup

    # 1. Launch assessment with loopback target
    payload = {
        "name": "Unit Test Assessment",
        "targets": ["127.0.0.1"],
        "ports": "54321",
        "concurrency": 10,
        "rate_limit": 100,
        "timeout": 0.5,
        "allow_public": False,
        "fingerprint": False,
        "assess": False,
        "correlate_cves": False,
    }
    launch_res = client.post("/api/v1/assessments", json=payload)
    assert launch_res.status_code == 202
    data = launch_res.json()
    assessment_id = data["assessment_id"]
    assert data["name"] == "Unit Test Assessment"
    assert data["status"] == "running"

    # 2. List assessments
    list_res = client.get("/api/v1/assessments")
    assert list_res.status_code == 200
    assessments = list_res.json()
    assert len(assessments) >= 1
    assert any(a["id"] == assessment_id for a in assessments)

    # 3. Get assessment detail
    detail_res = client.get(f"/api/v1/assessments/{assessment_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == assessment_id
    assert detail["name"] == "Unit Test Assessment"
    assert "scope_config" in detail

    # 4. Cancel assessment
    cancel_res = client.post(f"/api/v1/assessments/{assessment_id}/cancel")
    assert cancel_res.status_code == 200
    msg = cancel_res.json()["message"].lower()
    assert "cancelled" in msg or "completed" in msg

    # 5. Non-existent assessment returns 404
    not_found = client.get("/api/v1/assessments/00000000-0000-0000-0000-000000000000")
    assert not_found.status_code == 404

    # 6. Delete assessment
    del_res = client.delete(f"/api/v1/assessments/{assessment_id}")
    assert del_res.status_code == 200
    assert "deleted successfully" in del_res.json()["message"]

    # Verify deleted
    verify_del = client.get(f"/api/v1/assessments/{assessment_id}")
    assert verify_del.status_code == 404
