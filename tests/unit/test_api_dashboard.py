"""Tests for web dashboard static serving integration."""

from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings


def test_api_root_dashboard_link():
    """Verify API root endpoint advertises dashboard when web build exists."""
    settings = APISettings(api_key=None)
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "dashboard" in data
        assert data["dashboard"] == "/ui"


def test_dashboard_ui_html_served():
    """Verify /ui serves index.html."""
    settings = APISettings(api_key=None)
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get("/ui")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "ReconForge" in response.text
        assert "root" in response.text


def test_dashboard_subpath_catchall():
    """Verify client-side routes under /ui/{catchall} serve index.html."""
    settings = APISettings(api_key=None)
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get("/ui/assessments")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "ReconForge" in response.text


def test_dashboard_shield_icon_served():
    """Verify /shield.svg is served cleanly."""
    settings = APISettings(api_key=None)
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.get("/shield.svg")
        assert response.status_code == 200
        assert "image/svg+xml" in response.headers.get("content-type", "")
