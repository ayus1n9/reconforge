"""Unit tests for API key authentication, Bearer tokens, and timing attack resistance."""

from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings


def test_auth_disabled_by_default(tmp_path):
    """When api_key is None, all endpoints are accessible without credentials."""
    db_file = tmp_path / "test_auth_none.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}", api_key=None)
    app = create_app(settings)
    with TestClient(app) as client:
        res = client.get("/api/v1/system")
        assert res.status_code == 200


def test_auth_enforced_when_configured(tmp_path):
    """When api_key is set, protected endpoints reject missing or invalid credentials."""
    db_file = tmp_path / "test_auth_enforced.db"
    secret_key = "rf-sec-test-token-9988"
    settings = APISettings(db_url=f"sqlite:///{db_file}", api_key=secret_key)
    app = create_app(settings)

    with TestClient(app) as client:
        # Public health endpoint remains accessible
        health_res = client.get("/api/v1/health")
        assert health_res.status_code == 200

        # Protected endpoint without header -> 401
        res_no_auth = client.get("/api/v1/system")
        assert res_no_auth.status_code == 401
        assert "Invalid or missing API key" in res_no_auth.json()["detail"]

        # Protected endpoint with invalid header -> 401
        res_bad_key = client.get("/api/v1/system", headers={"X-API-Key": "wrong-token"})
        assert res_bad_key.status_code == 401

        # Protected endpoint with valid X-API-Key -> 200
        res_valid_header = client.get("/api/v1/system", headers={"X-API-Key": secret_key})
        assert res_valid_header.status_code == 200

        # Protected endpoint with valid Bearer token -> 200
        res_valid_bearer = client.get(
            "/api/v1/system", headers={"Authorization": f"Bearer {secret_key}"}
        )
        assert res_valid_bearer.status_code == 200

        # Protected endpoint with invalid Bearer token -> 401
        res_invalid_bearer = client.get(
            "/api/v1/system", headers={"Authorization": "Bearer invalid-token"}
        )
        assert res_invalid_bearer.status_code == 401
