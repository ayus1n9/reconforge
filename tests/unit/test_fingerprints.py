"""Unit tests for protocol service fingerprint probes and banner sanitization."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconforge.core.enums import ObservationConfidence
from reconforge.fingerprinting.probes.base import sanitize_banner
from reconforge.fingerprinting.probes.database_probe import DatabaseProbe
from reconforge.fingerprinting.probes.ftp_probe import FTPProbe
from reconforge.fingerprinting.probes.http_probe import HTTPProbe
from reconforge.fingerprinting.probes.smtp_probe import SMTPProbe
from reconforge.fingerprinting.probes.ssh_probe import SSHProbe
from reconforge.fingerprinting.service_detector import ServiceDetector


def make_mock_writer():
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    return writer


def test_sanitize_banner():
    # Strips control codes and trims
    dirty = b"SSH-2.0-OpenSSH_8.9p1\r\n\x00\x1b[31mRed\x1b[0m\t"
    cleaned = sanitize_banner(dirty, max_length=50)
    assert "SSH-2.0-OpenSSH_8.9p1" in cleaned
    assert "\x00" not in cleaned
    assert "\r" not in cleaned
    assert "\n" not in cleaned

    # Length capping
    long_banner = "A" * 500
    capped = sanitize_banner(long_banner, max_length=100)
    assert len(capped) == 100


@pytest.mark.asyncio
async def test_ssh_probe_parsing():
    probe = SSHProbe()
    raw_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    mock_reader = AsyncMock()
    mock_reader.readline.return_value = raw_banner
    mock_writer = make_mock_writer()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        fp = await probe.probe("127.0.0.1", 22)
        assert fp is not None
        assert fp.service_name == "ssh"
        assert fp.product == "OpenSSH"
        assert fp.version == "8.9p1"
        assert fp.confidence == ObservationConfidence.HIGH
        assert fp.cpe_candidate == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"


@pytest.mark.asyncio
async def test_http_probe_parsing():
    probe = HTTPProbe()
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Sun, 25 Oct 2026 10:00:00 GMT\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n\r\n"
    )

    mock_reader = AsyncMock()
    mock_reader.read.return_value = http_resp
    mock_writer = make_mock_writer()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        fp = await probe.probe("127.0.0.1", 80)
        assert fp is not None
        assert fp.service_name == "http"
        assert fp.product == "nginx"
        assert fp.version == "1.24.0"
        assert fp.confidence == ObservationConfidence.HIGH


@pytest.mark.asyncio
async def test_smtp_probe_parsing():
    probe = SMTPProbe()
    smtp_greeting = b"220 mail.corp.example ESMTP Postfix (Ubuntu)\r\n"

    mock_reader = AsyncMock()
    mock_reader.readline.return_value = smtp_greeting
    mock_writer = make_mock_writer()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        fp = await probe.probe("127.0.0.1", 25)
        assert fp is not None
        assert fp.service_name == "smtp"
        assert fp.product == "Postfix"


@pytest.mark.asyncio
async def test_ftp_probe_parsing():
    probe = FTPProbe()
    ftp_greeting = b"220 (vsFTPd 3.0.3)\r\n"

    mock_reader = AsyncMock()
    mock_reader.readline.return_value = ftp_greeting
    mock_writer = make_mock_writer()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        fp = await probe.probe("127.0.0.1", 21)
        assert fp is not None
        assert fp.service_name == "ftp"
        assert fp.product == "vsftpd"
        assert fp.version == "3.0.3"
        assert fp.confidence == ObservationConfidence.HIGH


@pytest.mark.asyncio
async def test_redis_database_probe():
    probe = DatabaseProbe()
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"+PONG\r\n"
    mock_writer = make_mock_writer()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        fp = await probe.probe("127.0.0.1", 6379)
        assert fp is not None
        assert fp.service_name == "redis"
        assert fp.product == "Redis"
        assert fp.confidence == ObservationConfidence.HIGH


@pytest.mark.asyncio
async def test_mysql_database_probe():
    probe = DatabaseProbe()
    # Mock MySQL handshake packet (proto 10, server version 8.0.35\0)
    mysql_handshake = b"\x30\x00\x00\x00\x0a8.0.35-0ubuntu0.22.04.1\x00\x01\x02\x03\x04"

    mock_reader = AsyncMock()
    mock_reader.read.return_value = mysql_handshake
    mock_writer = make_mock_writer()

    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        fp = await probe.probe("127.0.0.1", 3306)
        assert fp is not None
        assert fp.service_name == "mysql"
        assert fp.product == "MySQL"
        assert "8.0.35" in fp.version


@pytest.mark.asyncio
async def test_service_detector_unknown_fallback():
    detector = ServiceDetector(probes=[])
    fp = await detector.identify_service("127.0.0.1", 9999)
    assert fp.service_name == "unknown"
    assert fp.confidence == ObservationConfidence.UNKNOWN
