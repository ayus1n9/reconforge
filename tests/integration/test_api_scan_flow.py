"""Integration test for full asynchronous network scanning, exposure assessment, and reporting via REST API."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from reconforge.api.app import create_app
from reconforge.api.config import APISettings


class MockTCPServer:
    """Ephemeral TCP test service on loopback."""

    def __init__(self, banner: bytes = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"):
        self.banner = banner
        self.server: asyncio.Server | None = None
        self.port: int = 0

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            writer.write(self.banner)
            await writer.drain()
            await asyncio.sleep(0.05)
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


@pytest.fixture
def api_test_client(tmp_path):
    db_file = tmp_path / "test_api_flow.db"
    settings = APISettings(db_url=f"sqlite:///{db_file}")
    app = create_app(settings)
    with TestClient(app) as client:
        yield client


@pytest.mark.asyncio
async def test_full_async_api_scan_pipeline(api_test_client):
    """End-to-end integration: launch scan via API, poll status, check inventory, posture & report."""
    mock_service = MockTCPServer(banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    port = await mock_service.start()

    try:
        # 1. Dispatch scan via REST API
        launch_payload = {
            "name": "Integration API Scan",
            "targets": ["127.0.0.1"],
            "ports": str(port),
            "concurrency": 10,
            "rate_limit": 100,
            "timeout": 1.0,
            "allow_public": False,
            "fingerprint": True,
            "assess": True,
            "correlate_cves": False,
        }
        res_launch = api_test_client.post("/api/v1/assessments", json=launch_payload)
        assert res_launch.status_code == 202
        assessment_id = res_launch.json()["assessment_id"]

        # 2. Poll until completed (timeout 10s)
        completed = False
        for _ in range(50):
            res_poll = api_test_client.get(f"/api/v1/assessments/{assessment_id}")
            assert res_poll.status_code == 200
            data = res_poll.json()
            if data["status"] == "completed":
                completed = True
                break
            await asyncio.sleep(0.1)

        assert completed is True, f"Scan failed to complete. Final state: {data}"

        # 3. Verify asset inventory
        res_assets = api_test_client.get("/api/v1/assets")
        assert res_assets.status_code == 200
        assets = res_assets.json()
        assert len(assets) >= 1
        assert any(a["ip_address"] == "127.0.0.1" for a in assets)

        # 4. Check asset detail and service identification
        res_detail = api_test_client.get("/api/v1/assets/127.0.0.1")
        assert res_detail.status_code == 200
        detail = res_detail.json()
        assert any(s["port"] == port for s in detail["services"])

        # 5. Check risk posture endpoint
        res_scoring = api_test_client.get(f"/api/v1/scoring/{assessment_id}")
        assert res_scoring.status_code == 200
        scoring = res_scoring.json()
        assert scoring["assessment_id"] == assessment_id
        assert "risk_score" in scoring

        # 6. Check report endpoint
        res_report = api_test_client.get(f"/api/v1/reports/{assessment_id}?format=html")
        assert res_report.status_code == 200
        assert "<!DOCTYPE html>" in res_report.text
        assert "127.0.0.1" in res_report.text

    finally:
        await mock_service.stop()
