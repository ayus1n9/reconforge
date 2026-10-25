"""Integration tests for AsyncTCPScanner against local socket fixtures."""

import asyncio
import socket
from unittest.mock import patch

import pytest

from reconforge.core.enums import AddressFamily, PortState, ScanStatus
from reconforge.core.models import ScanConfig, ScanTarget, TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.discovery.tcp_scanner import AsyncTCPScanner


@pytest.mark.asyncio
async def test_tcp_scan_open_port(mock_tcp_server):
    ip, port = mock_tcp_server
    scope = TargetScope(
        allowed_targets=[ip],
        allowed_ports=str(port),
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(scope_manager=mgr, config=ScanConfig(timeout_seconds=1.0))
    target = ScanTarget(ip=ip, address_family=AddressFamily.IPV4)

    obs = await scanner.scan_single_port(target, port)
    assert obs.state == PortState.OPEN
    assert obs.port == port
    assert obs.target_ip == ip
    assert obs.response_time_ms is not None
    assert obs.response_time_ms >= 0.0


@pytest.mark.asyncio
async def test_tcp_scan_closed_port():
    # Find an unused port by binding and immediately closing
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    unused_port = sock.getsockname()[1]
    sock.close()

    scope = TargetScope(
        allowed_targets=["127.0.0.1"],
        allowed_ports=str(unused_port),
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(scope_manager=mgr, config=ScanConfig(timeout_seconds=1.0))
    target = ScanTarget(ip="127.0.0.1", address_family=AddressFamily.IPV4)

    obs = await scanner.scan_single_port(target, unused_port)
    assert obs.state == PortState.CLOSED
    assert obs.port == unused_port


@pytest.mark.asyncio
async def test_tcp_scan_timeout_port():
    # Test handling of timeout when a target connection exceeds timeout_seconds
    scope = TargetScope(
        allowed_targets=["127.0.0.1"],
        allowed_ports="8080",
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(scope_manager=mgr, config=ScanConfig(timeout_seconds=0.1))
    target = ScanTarget(ip="127.0.0.1", address_family=AddressFamily.IPV4)

    async def mock_slow_connect(*args, **kwargs):
        await asyncio.sleep(2.0)
        return (None, None)

    with patch("asyncio.open_connection", side_effect=mock_slow_connect):
        obs = await scanner.scan_single_port(target, 8080)
        assert obs.state == PortState.TIMEOUT
        assert "timed out" in (obs.error_message or "").lower()


@pytest.mark.asyncio
async def test_tcp_scan_multi_target_and_summary(mock_tcp_server):
    ip, open_port = mock_tcp_server
    # Use another closed port
    closed_port = open_port + 1 if open_port < 65530 else open_port - 1

    scope = TargetScope(
        allowed_targets=[ip],
        allowed_ports=f"{open_port},{closed_port}",
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(
        scope_manager=mgr,
        config=ScanConfig(timeout_seconds=0.5, concurrency=5),
    )
    targets = [ScanTarget(ip=ip, address_family=AddressFamily.IPV4)]

    observations, summary = await scanner.scan_targets(targets, [open_port, closed_port])
    assert len(observations) == 2
    assert summary.targets_assessed == 1
    assert summary.probes_attempted == 2
    assert summary.open_count == 1
    assert summary.status == ScanStatus.COMPLETED


@pytest.mark.asyncio
async def test_tcp_scan_cancellation():
    scope = TargetScope(
        allowed_targets=["127.0.0.1"],
        allowed_ports="8080-8089",
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(
        scope_manager=mgr,
        config=ScanConfig(timeout_seconds=5.0, concurrency=2),
    )
    target = ScanTarget(ip="127.0.0.1", address_family=AddressFamily.IPV4)

    # Mock connect to hang so cancellation triggers mid-scan
    async def mock_hanging_connect(*args, **kwargs):
        await asyncio.sleep(10.0)
        return (None, None)

    with patch("asyncio.open_connection", side_effect=mock_hanging_connect):

        async def run_and_cancel():
            scan_task = asyncio.create_task(scanner.scan_targets([target], list(range(8080, 8085))))
            await asyncio.sleep(0.05)
            scanner.cancel()
            return await scan_task

        observations, summary = await run_and_cancel()
        assert summary.status == ScanStatus.CANCELLED
        # Verify that at least one observation was marked NOT_SCANNED due to cancellation
        assert any(obs.state == PortState.NOT_SCANNED for obs in observations)
