"""Unit tests for Common Platform Enumeration (CPE 2.3) engine."""

import pytest

from reconforge.intelligence.cpe import CPE


def test_cpe23_serialization():
    cpe = CPE(
        part="a",
        vendor="openssh",
        product="openssh",
        version="8.9p1",
    )
    expected = "cpe:2.3:a:openssh:openssh:8.9p1:*:*:*:*:*:*:*"
    assert cpe.to_cpe23() == expected


def test_cpe22_uri_serialization():
    cpe = CPE(
        part="a",
        vendor="apache",
        product="http_server",
        version="2.4.49",
    )
    assert cpe.to_uri() == "cpe:/a:apache:http_server:2.4.49"

    wildcard_cpe = CPE(part="a", vendor="redis", product="redis", version="*")
    assert wildcard_cpe.to_uri() == "cpe:/a:redis:redis"


def test_cpe_from_valid_cpe23_string():
    cpe_str = "cpe:2.3:a:openssh:openssh:8.9p1:*:*:*:*:*:*:*"
    cpe = CPE.from_string(cpe_str)
    assert cpe.part == "a"
    assert cpe.vendor == "openssh"
    assert cpe.product == "openssh"
    assert cpe.version == "8.9p1"


def test_cpe_from_valid_cpe22_uri():
    cpe_str = "cpe:/a:f5:nginx:1.18.0"
    cpe = CPE.from_string(cpe_str)
    assert cpe.part == "a"
    assert cpe.vendor == "f5"
    assert cpe.product == "nginx"
    assert cpe.version == "1.18.0"


def test_cpe_from_invalid_string():
    with pytest.raises(ValueError, match="Unrecognized CPE string format"):
        CPE.from_string("invalid_format_string")

    with pytest.raises(ValueError, match="insufficient components"):
        CPE.from_string("cpe:2.3:a:short")


def test_cpe_sanitization():
    cpe = CPE(
        part="a",
        vendor="Apache Software Foundation",
        product="HTTP Server",
        version="2.4.49 (Unix)",
    )
    cpe23 = cpe.to_cpe23()
    assert " " not in cpe23
    assert "(" not in cpe23
    assert ")" not in cpe23


def test_cpe_from_service_mapping():
    # OpenSSH
    ssh_cpe = CPE.from_service("ssh", product="OpenSSH", version="8.9p1")
    assert ssh_cpe.vendor == "openssh"
    assert ssh_cpe.product == "openssh"
    assert ssh_cpe.version == "8.9p1"

    # Apache
    http_cpe = CPE.from_service("http", product="Apache httpd", version="2.4.49")
    assert http_cpe.vendor == "apache"
    assert http_cpe.product == "http_server"

    # Redis
    redis_cpe = CPE.from_service("redis", version="6.0.9")
    assert redis_cpe.vendor == "redis"
    assert redis_cpe.product == "redis"
    assert redis_cpe.version == "6.0.9"

    # Unknown service fallback
    unk_cpe = CPE.from_service("custom_internal_daemon", version="1.0")
    assert unk_cpe.vendor == "custom_internal_daemon"
    assert unk_cpe.product == "custom_internal_daemon"
    assert unk_cpe.version == "1.0"
