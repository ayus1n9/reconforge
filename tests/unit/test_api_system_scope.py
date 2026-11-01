"""Unit tests for system diagnostics and scope boundary validation endpoints."""

import pytest
from fastapi.testclient import TestClient

from reconforge import __version__
from reconforge.api.app import create_app
from reconforge.api.config import APISettings


@pytest.fixture
def client(tmp_path):
    db_file = tmp_path / "test_sys_scope.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client):
    """Verify health endpoint returns ok status, version, and timestamp."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["version"] == __version__
    assert "timestamp" in data


def test_system_info(client):
    """Verify system diagnostics endpoint returns platform and database status."""
    res = client.get("/api/v1/system")
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == __version__
    assert data["database_status"] == "connected"
    assert data["rules_count"] >= 15
    assert isinstance(data["total_assets"], int)


def test_scope_validation_success(client):
    """Verify valid scope definition returns total target and port counts."""
    payload = {
        "targets": ["10.0.0.0/24", "192.168.1.50"],
        "ports": "22,80,443,8000-8010",
        "allow_public": False,
        "excluded_targets": ["10.0.0.1"],
    }
    res = client.post("/api/v1/scope/validate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True
    assert data["total_targets"] > 1
    assert data["allowed_ports_count"] == 14  # 3 single + 11 range


def test_scope_validation_invalid_port(client):
    """Verify invalid port strings return 400 Bad Request."""
    payload = {
        "targets": ["10.0.0.1"],
        "ports": "invalid,99999",
    }
    res = client.post("/api/v1/scope/validate", json=payload)
    assert res.status_code == 400
    assert "Invalid port specification" in res.json()["detail"]


def test_scope_validation_cloud_metadata_rejection(client):
    """Verify SSRF cloud metadata endpoint (169.254.169.254) is blocked with 403."""
    payload = {
        "targets": ["169.254.169.254"],
        "ports": "80",
    }
    res = client.post("/api/v1/scope/validate", json=payload)
    assert res.status_code == 403
    assert "Scope authorization violation" in res.json()["detail"]


def test_scope_validation_unauthorized_public_ip(client):
    """Verify unauthorized public IP target is blocked with 403 when allow_public is false."""
    payload = {
        "targets": ["8.8.8.8"],
        "ports": "53",
        "allow_public": False,
    }
    res = client.post("/api/v1/scope/validate", json=payload)
    assert res.status_code == 403
    assert "public internet scanning is not authorized" in res.json()["detail"].lower()
