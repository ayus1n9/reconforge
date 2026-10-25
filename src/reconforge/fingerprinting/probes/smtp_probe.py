"""SMTP service identification probe compliant with RFC 5321."""

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

logger = logging.getLogger("reconforge.probes.smtp")


class SMTPProbe(BaseServiceProbe):
    """Identifies SMTP mail transfer agents by inspecting RFC 5321 service greetings."""

    name: str = "smtp"
    default_ports = (25, 587, 465)

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
            logger.debug("SMTP probe error on %s:%d: %s", ip, port, err)
            return None
        finally:
            await safe_close_writer(writer)

        if not greeting.startswith("220"):
            return None

        product = None
        version = None

        lower = greeting.lower()
        if "postfix" in lower:
            product = "Postfix"
        elif "exim" in lower:
            product = "Exim"
            match = re.search(r"exim\s+([0-9._-]+)", greeting, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "sendmail" in lower:
            product = "Sendmail"
            match = re.search(r"sendmail[/ ]([0-9._-]+)", greeting, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif "microsoft" in lower or "exchange" in lower:
            product = "Microsoft Exchange SMTP"
        else:
            product = "Generic SMTP Service"

        confidence = ObservationConfidence.HIGH if version else ObservationConfidence.MEDIUM

        return ServiceFingerprint(
            service_name="smtp",
            transport_protocol=TransportProtocol.TCP,
            product=product,
            version=version,
            confidence=confidence,
            banner_snippet=sanitize_banner(greeting),
            probe_method="smtp_greeting_banner",
            limitations="Observed from initial RFC 5321 220 banner without sending mail or VRFY commands.",
        )
