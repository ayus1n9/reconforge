"""Unit tests for FastAPI app initialization, middleware, and CORS configuration."""

import pytest
from fastapi.testclient import TestClient

from reconforge import __version__
from reconforge.api.app import create_app
from reconforge.api.config import APISettings


@pytest.fixture
def test_app(tmp_path):
    db_file = tmp_path / "test_api.db"
    settings = APISettings(
        db_url=f"sqlite:///{db_file}",
        cors_origins=["http://localhost:3000", "http://testserver"],
        max_upload_size_bytes=1024 * 1024,  # 1 MB for testing
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


def test_root_endpoint(test_app):
    """Verify root endpoint returns API navigation links and current version."""
    response = test_app.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == __version__
    assert "/docs" in data["docs"]
    assert "/api/v1/health" in data["health"]


def test_cors_headers(test_app):
    """Verify CORS middleware attaches appropriate Access-Control headers."""
    response = test_app.options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_request_timing_header(test_app):
    """Verify RequestTimingMiddleware attaches X-Process-Time header."""
    response = test_app.get("/api/v1/health")
    assert response.status_code == 200
    assert "x-process-time" in response.headers
    process_time = float(response.headers["x-process-time"])
    assert process_time >= 0.0


def test_payload_size_limit_rejection(test_app):
    """Verify PayloadSizeLimitMiddleware rejects oversized requests with 413."""
    oversized_data = "X" * (1024 * 1024 + 100)  # > 1 MB
    response = test_app.post(
        "/api/v1/scope/validate",
        content=oversized_data,
        headers={"Content-Type": "application/json", "Content-Length": str(len(oversized_data))},
    )
    assert response.status_code == 413
    assert "exceeds maximum allowed limit" in response.json()["detail"]
