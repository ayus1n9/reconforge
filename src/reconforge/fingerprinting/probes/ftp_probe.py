"""FTP service identification probe compliant with RFC 959."""

import asyncio
import logging
import re

from reconforge.core.enums import ObservationConfidence, TransportProtocol
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.fingerprinting.probes.base import (
    BaseServiceProbe,
    safe_close_writer,
    sanitize_banner,
)

logger = logging.getLogger("reconforge.probes.ftp")


class FTPProbe(BaseServiceProbe):
    """Identifies FTP server daemons by inspecting RFC 959 initial greeting banners."""

    name: str = "ftp"
    default_ports = (21, 2121)

    async def probe(self, ip: str, port: int, timeout: float = 3.0) -> ServiceFingerprint | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except Exception:
            return None

        greeting = ""
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            greeting = raw.decode("latin-1", errors="replace").strip()
            # Send polite QUIT
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except Exception as err:
            logger.debug("FTP probe error on %s:%d: %s", ip, port, err)
            return None
        finally:
            await safe_close_writer(writer)

        if not greeting.startswith("220"):
            return None

        product = None
        version = None

        lower = greeting.lower()
        if "vsftpd" in lower:
            product = "vsftpd"
            match = re.search(r"vsftpd\s+([0-9._-]+)", greeting, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "proftpd" in lower:
            product = "ProFTPD"
            match = re.search(r"proftpd\s+([0-9._-]+)", greeting, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "pure-ftpd" in lower:
            product = "Pure-FTPd"
        elif "filezilla" in lower:
            product = "FileZilla Server"
            match = re.search(r"filezilla server\s+([0-9._-]+)", greeting, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "microsoft" in lower:
            product = "Microsoft FTP Service"
        else:
            product = "Generic FTP Service"

        confidence = ObservationConfidence.HIGH if version else ObservationConfidence.MEDIUM

        return ServiceFingerprint(
            service_name="ftp",
            transport_protocol=TransportProtocol.TCP,
            product=product,
            version=version,
            confidence=confidence,
            banner_snippet=sanitize_banner(greeting),
            probe_method="ftp_greeting_banner",
            limitations="Observed from initial RFC 959 220 banner without attempting authentication.",
        )
