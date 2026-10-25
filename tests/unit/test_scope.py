"""Unit tests for ScopeManager and network boundary enforcement."""

import pytest

from reconforge.core.exceptions import (
    InvalidPortError,
    ScopeViolationError,
)
from reconforge.core.models import TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.utils.network import parse_ports


def test_parse_ports_valid():
    assert parse_ports("80") == [80]
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("80-82") == [80, 81, 82]
    assert parse_ports("22, 80-82, 443") == [22, 80, 81, 82, 443]
    assert parse_ports([80, 443, "8080-8082"]) == [80, 443, 8080, 8081, 8082]


def test_parse_ports_invalid():
    with pytest.raises(InvalidPortError):
        parse_ports("0")
    with pytest.raises(InvalidPortError):
        parse_ports("65536")
    with pytest.raises(InvalidPortError):
        parse_ports("100-50")
    with pytest.raises(InvalidPortError):
        parse_ports("invalid")
    with pytest.raises(InvalidPortError):
        parse_ports("")


def test_scope_ip_inclusion_and_exclusion(sample_scope_manager: ScopeManager):
    # Single allowed IP
    assert sample_scope_manager.is_ip_allowed("127.0.0.1") is True

    # Subnet allowed IP
    assert sample_scope_manager.is_ip_allowed("10.0.0.5") is True
    assert sample_scope_manager.is_ip_allowed("10.0.0.1") is True

    # Excluded IP inside allowed subnet
    assert sample_scope_manager.is_ip_allowed("10.0.0.254") is False

    # Out of scope IP
    assert sample_scope_manager.is_ip_allowed("192.168.1.1") is False


def test_scope_port_validation(sample_scope_manager: ScopeManager):
    assert sample_scope_manager.is_port_allowed(80) is True
    assert sample_scope_manager.is_port_allowed(443) is True
    assert sample_scope_manager.is_port_allowed(8005) is True
    assert sample_scope_manager.is_port_allowed(25) is False
    assert sample_scope_manager.is_port_allowed(9000) is False


def test_scope_public_ip_guard():
    # Public IP rejected when allow_public_targets is False
    scope = TargetScope(
        allowed_targets=["8.8.8.8", "1.1.1.1"],
        allowed_ports="53",
        allow_public_targets=False,
    )
    mgr = ScopeManager(scope)
    assert mgr.is_ip_allowed("8.8.8.8") is False
    with pytest.raises(ScopeViolationError, match="public internet scanning is not authorized"):
        mgr.validate_target_and_port("8.8.8.8", 53)

    # Allowed when explicitly authorized
    scope_pub = TargetScope(
        allowed_targets=["8.8.8.8"],
        allowed_ports="53",
        allow_public_targets=True,
    )
    mgr_pub = ScopeManager(scope_pub)
    assert mgr_pub.is_ip_allowed("8.8.8.8") is True


def test_scope_cloud_metadata_guard():
    scope = TargetScope(
        allowed_targets=["169.254.169.254", "169.254.0.0/16"],
        allowed_ports="80",
        allow_cloud_metadata=False,
    )
    mgr = ScopeManager(scope)
    assert mgr.is_ip_allowed("169.254.169.254") is False
    with pytest.raises(ScopeViolationError, match="cloud metadata"):
        mgr.validate_target_and_port("169.254.169.254", 80)


def test_scope_expand_static_targets():
    scope = TargetScope(
        allowed_targets=["127.0.0.1", "10.0.0.0/30"],
        excluded_targets=["10.0.0.2"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)
    targets = mgr.expand_static_targets()
    ip_list = [t.ip for t in targets]

    assert "127.0.0.1" in ip_list
    # /30 usable host IPs: 10.0.0.1, 10.0.0.2 (excluded)
    assert "10.0.0.1" in ip_list
    assert "10.0.0.2" not in ip_list


def test_scope_oversized_cidr_prevention():
    # /16 has 65,536 hosts, exceeding safe limit of 4096
    scope = TargetScope(
        allowed_targets=["10.1.0.0/16"],
        allowed_ports="80",
    )
    mgr = ScopeManager(scope)
    with pytest.raises(ScopeViolationError, match="exceeding safe single-scan limit"):
        mgr.expand_static_targets()
