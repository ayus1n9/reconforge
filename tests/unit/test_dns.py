"""Unit tests for DNSResolver, DNS pinning, and DNS rebinding protections."""

import asyncio
import socket
from unittest.mock import patch

import pytest

from reconforge.core.exceptions import DNSResolutionError, ScopeViolationError
from reconforge.core.models import TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.discovery.dns_resolver import DNSResolver


@pytest.mark.asyncio
async def test_dns_resolution_and_pinning():
    scope = TargetScope(
        allowed_targets=["127.0.0.1", "scanme.internal"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)
    resolver = DNSResolver(scope_manager=mgr, timeout_seconds=2.0)

    # Mock getaddrinfo to return 127.0.0.1 for scanme.internal
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]

    with patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=mock_addrinfo):
        targets = await resolver.resolve_hostname("scanme.internal")
        assert len(targets) == 1
        assert targets[0].ip == "127.0.0.1"
        assert targets[0].hostname == "scanme.internal"
        assert targets[0].is_pinned is True


@pytest.mark.asyncio
async def test_dns_rebinding_prevention():
    # Target scope allows "attacker.domain", but ONLY allows IPs in 10.0.0.0/24
    scope = TargetScope(
        allowed_targets=["10.0.0.0/24", "attacker.domain"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)
    resolver = DNSResolver(scope_manager=mgr, timeout_seconds=2.0)

    # Attacker DNS attempts rebinding to AWS metadata or loopback
    mock_rebinding = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0)),
    ]

    with patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=mock_rebinding):
        with pytest.raises(ScopeViolationError, match="DNS Rebinding / Scope Violation"):
            await resolver.resolve_hostname("attacker.domain")


@pytest.mark.asyncio
async def test_dns_unauthorized_hostname():
    scope = TargetScope(
        allowed_targets=["127.0.0.1"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)
    resolver = DNSResolver(scope_manager=mgr)

    with pytest.raises(ScopeViolationError, match="not authorized in assessment scope"):
        await resolver.resolve_hostname("unauthorized.com")


@pytest.mark.asyncio
async def test_dns_lookup_failure():
    scope = TargetScope(
        allowed_targets=["nonexistent.internal"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)
    resolver = DNSResolver(scope_manager=mgr)

    with patch.object(
        asyncio.get_running_loop(),
        "getaddrinfo",
        side_effect=socket.gaierror(socket.EAI_NONAME, "Name not known"),
    ):
        with pytest.raises(DNSResolutionError, match="DNS lookup failed"):
            await resolver.resolve_hostname("nonexistent.internal")
