"""Integration tests for live local mock services identified by AsyncTCPScanner."""

import asyncio

import pytest

from reconforge.core.enums import AddressFamily, ObservationConfidence, PortState
from reconforge.core.models import ScanConfig, ScanTarget, TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.discovery.tcp_scanner import AsyncTCPScanner


@pytest.mark.asyncio
async def test_live_local_http_service_identification():
    # Start a mock HTTP server
    async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await reader.read(1024)
            response = b"HTTP/1.1 200 OK\r\nServer: Caddy/2.6.4\r\nContent-Length: 2\r\n\r\nOK"
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_http, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        scope = TargetScope(allowed_targets=["127.0.0.1"], allowed_ports=str(port))
        mgr = ScopeManager(scope)
        scanner = AsyncTCPScanner(
            scope_manager=mgr,
            config=ScanConfig(timeout_seconds=2.0, fingerprint_services=True),
        )
        target = ScanTarget(ip="127.0.0.1", address_family=AddressFamily.IPV4)

        observations, summary = await scanner.scan_targets([target], [port])
        assert len(observations) == 1
        obs = observations[0]
        assert obs.state == PortState.OPEN
        assert obs.service is not None
        assert obs.service.service_name == "http"
        assert obs.service.product == "Caddy"
        assert obs.service.version == "2.6.4"
        assert obs.service.confidence == ObservationConfidence.HIGH
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_live_local_ssh_service_identification():
    # Start a mock SSH server
    async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            writer.write(b"SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n")
            await writer.drain()
            await asyncio.sleep(0.5)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_ssh, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        scope = TargetScope(allowed_targets=["127.0.0.1"], allowed_ports=str(port))
        mgr = ScopeManager(scope)
        scanner = AsyncTCPScanner(
            scope_manager=mgr,
            config=ScanConfig(timeout_seconds=2.0, fingerprint_services=True),
        )
        target = ScanTarget(ip="127.0.0.1", address_family=AddressFamily.IPV4)

        observations, summary = await scanner.scan_targets([target], [port])
        assert len(observations) == 1
        obs = observations[0]
        assert obs.state == PortState.OPEN
        assert obs.service is not None
        assert obs.service.service_name == "ssh"
        assert obs.service.product == "OpenSSH"
        assert obs.service.version == "9.3p1"
        assert obs.service.confidence == ObservationConfidence.HIGH
    finally:
        server.close()
        await server.wait_closed()
