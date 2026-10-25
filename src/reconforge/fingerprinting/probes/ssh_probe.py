"""SSH protocol identification probe compliant with RFC 4253."""

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

logger = logging.getLogger("reconforge.probes.ssh")


class SSHProbe(BaseServiceProbe):
    """Identifies SSH endpoints by reading initial RFC 4253 protocol identification string."""

    name: str = "ssh"
    default_ports = (22, 2222)

    async def probe(self, ip: str, port: int, timeout: float = 3.0) -> ServiceFingerprint | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except Exception:
            return None

        banner_line = ""
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner_line = raw.decode("latin-1", errors="replace").strip()
        except Exception as err:
            logger.debug("SSH banner read error on %s:%d: %s", ip, port, err)
            return None
        finally:
            await safe_close_writer(writer)

        if not banner_line.startswith("SSH-"):
            return None

        # Format: SSH-protoversion-softwareversion[ comments]
        match = re.match(r"^SSH-([0-9.]+)-([A-Za-z0-9_.-]+)(?:\s+(.*))?", banner_line)
        protocol_ver = match.group(1) if match else "2.0"
        software = match.group(2) if match else "Unknown"
        comment = match.group(3) if match else None

        product = None
        version = None

        if "_" in software:
            parts = software.split("_", 1)
            product = parts[0]
            version = parts[1]
        elif "-" in software:
            parts = software.split("-", 1)
            product = parts[0]
            version = parts[1]
        else:
            product = software

        cpe = None
        if product and product.lower() == "openssh" and version:
            cpe = f"cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"

        return ServiceFingerprint(
            service_name="ssh",
            transport_protocol=TransportProtocol.TCP,
            product=product,
            version=version,
            cpe_candidate=cpe,
            confidence=ObservationConfidence.HIGH,
            banner_snippet=sanitize_banner(banner_line),
            probe_method="ssh_protocol_banner",
            limitations="Verified via RFC 4253 identification string; no key exchange or authentication attempted.",
            extra_metadata={
                "ssh_protocol_version": protocol_ver,
                "software_string": software,
                "system_comment": comment,
            },
        )
