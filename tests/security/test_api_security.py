"""Security and boundary audit tests for the FastAPI service."""

from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings


def test_api_ssrf_metadata_blocking(tmp_path):
    """Verify API rejects requests targeting cloud instance metadata (169.254.169.254) with 403."""
    db_file = tmp_path / "test_sec_ssrf.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)

    with TestClient(app) as client:
        payload = {
            "name": "Malicious SSRF Probe",
            "targets": ["169.254.169.254"],
            "ports": "80",
            "allow_public": False,
        }
        res = client.post("/api/v1/assessments", json=payload)
        assert res.status_code == 403
        assert "cloud metadata" in res.json()["detail"].lower()


def test_api_unauthorized_public_ip_blocking(tmp_path):
    """Verify API rejects public Internet targets without explicit allow_public flag."""
    db_file = tmp_path / "test_sec_public.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)

    with TestClient(app) as client:
        payload = {
            "name": "Unauthorized Public Target",
            "targets": ["1.1.1.1"],
            "ports": "443",
            "allow_public": False,
        }
        res = client.post("/api/v1/assessments", json=payload)
        assert res.status_code == 403
        assert "public internet scanning is not authorized" in res.json()["detail"].lower()


def test_api_payload_limit_enforcement(tmp_path):
    """Verify oversized request payloads are aborted with HTTP 413."""
    db_file = tmp_path / "test_sec_limit.db"
    # Set 500 KB limit for test
    settings = APISettings(db_url=f"sqlite:///{db_file}", max_upload_size_bytes=500 * 1024)
    app = create_app(settings)

    with TestClient(app) as client:
        oversized = "A" * (600 * 1024)
        res = client.post(
            "/api/v1/snapshots/import",
            content=oversized,
            headers={"Content-Type": "application/json", "Content-Length": str(len(oversized))},
        )
        assert res.status_code == 413
        assert "exceeds maximum allowed limit" in res.json()["detail"]


def test_api_auth_token_protection(tmp_path):
    """Verify authentication cannot be bypassed when API key is active."""
    db_file = tmp_path / "test_sec_auth.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}", api_key="super-secret-auth-key-12345")
    app = create_app(settings)

    with TestClient(app) as client:
        # Launch assessment without key -> 401
        res = client.post(
            "/api/v1/assessments",
            json={"name": "Unauthenticated Scan", "targets": ["127.0.0.1"], "ports": "80"},
        )
        assert res.status_code == 401

        # Delete assessment with forged key -> 401
        res_del = client.delete(
            "/api/v1/assessments/test-id", headers={"X-API-Key": "forged-token"}
        )
        assert res_del.status_code == 401
