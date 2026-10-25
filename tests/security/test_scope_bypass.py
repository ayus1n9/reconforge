"""Security tests: Scope bypass prevention, SSRF defense, and boundary enforcement."""

import pytest

from reconforge.core.enums import AddressFamily
from reconforge.core.exceptions import (
    InvalidTargetError,
    ScopeViolationError,
)
from reconforge.core.models import ScanTarget, TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.discovery.tcp_scanner import AsyncTCPScanner


@pytest.mark.asyncio
async def test_unauthorized_ip_rejected():
    scope = TargetScope(
        allowed_targets=["10.0.0.0/24"],
        allowed_ports="80,443",
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(scope_manager=mgr)

    # Target crafted with IP outside allowed subnet
    malicious_target = ScanTarget(ip="192.168.1.50", address_family=AddressFamily.IPV4)

    with pytest.raises(ScopeViolationError, match="outside the approved assessment scope"):
        await scanner.scan_single_port(malicious_target, 80)


@pytest.mark.asyncio
async def test_unauthorized_port_rejected():
    scope = TargetScope(
        allowed_targets=["127.0.0.1"],
        allowed_ports="80,443",
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(scope_manager=mgr)
    target = ScanTarget(ip="127.0.0.1", address_family=AddressFamily.IPV4)

    # Attempt to probe port 22 which is not in allowed_ports
    with pytest.raises(ScopeViolationError, match="outside the approved assessment port range"):
        await scanner.scan_single_port(target, 22)


@pytest.mark.asyncio
async def test_cloud_metadata_ssrf_protection():
    # Even if an attacker configures cloud metadata in allowed_targets,
    # the allow_cloud_metadata flag (default False) must block it
    scope = TargetScope(
        allowed_targets=["169.254.169.254"],
        allowed_ports="80",
        allow_cloud_metadata=False,
    )
    mgr = ScopeManager(scope)
    scanner = AsyncTCPScanner(scope_manager=mgr)
    target = ScanTarget(ip="169.254.169.254", address_family=AddressFamily.IPV4)

    with pytest.raises(ScopeViolationError, match="cloud metadata endpoints are forbidden"):
        await scanner.scan_single_port(target, 80)


def test_malformed_target_injection():
    with pytest.raises(InvalidTargetError):
        TargetScope(allowed_targets=["127.0.0.1; rm -rf /"])

    with pytest.raises(InvalidTargetError):
        TargetScope(allowed_targets=["10.0.0.0/99"])

    with pytest.raises(InvalidTargetError):
        TargetScope(allowed_targets=["not a hostname or ip!"])


def test_ipv6_scope_enforcement():
    scope = TargetScope(
        allowed_targets=["::1", "2001:db8::/32"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)

    assert mgr.is_ip_allowed("::1") is True
    assert mgr.is_ip_allowed("2001:db8::1") is True
    assert mgr.is_ip_allowed("2001:db9::1") is False  # Outside /32
