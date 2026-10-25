"""Safe, non-intrusive HTTP/1.1 service identification probe."""

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

logger = logging.getLogger("reconforge.probes.http")


class HTTPProbe(BaseServiceProbe):
    """Identifies HTTP web servers by sending minimal RFC 9112 HEAD/GET requests."""

    name: str = "http"
    default_ports = (80, 8080, 8000, 8888, 3000, 5000)

    async def probe(self, ip: str, port: int, timeout: float = 3.0) -> ServiceFingerprint | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except Exception:
            return None

        response_text = ""
        try:
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: ReconForge/0.2.0\r\nConnection: close\r\n\r\n"
            writer.write(request.encode("ascii"))
            await writer.drain()

            raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            response_text = raw.decode("latin-1", errors="replace")

            # If server returned 405 Method Not Allowed or 0 bytes, try minimal GET
            if not response_text or "405 Method Not Allowed" in response_text:
                await safe_close_writer(writer)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout,
                )
                get_request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: ReconForge/0.2.0\r\nConnection: close\r\n\r\n"
                writer.write(get_request.encode("ascii"))
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                response_text = raw.decode("latin-1", errors="replace")
        except Exception as err:
            logger.debug("HTTP probe communication error on %s:%d: %s", ip, port, err)
            return None
        finally:
            await safe_close_writer(writer)

        if not response_text or "HTTP/" not in response_text:
            return None

        lines = response_text.split("\r\n")
        status_line = lines[0].strip()

        # Check if plain HTTP was sent to an HTTPS port
        if "400 Bad Request" in status_line and (
            "https" in response_text.lower() or "ssl" in response_text.lower()
        ):
            return ServiceFingerprint(
                service_name="https",
                transport_protocol=TransportProtocol.TCP,
                product="SSL/TLS Web Server",
                version=None,
                confidence=ObservationConfidence.HIGH,
                banner_snippet=sanitize_banner(status_line),
                probe_method="http_ssl_redirect_detection",
                limitations="Server rejected plain HTTP request; indicates TLS is required.",
            )

        product = None
        version = None
        server_header = None
        powered_by = None

        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith("server:"):
                server_header = line[7:].strip()
            elif lower.startswith("x-powered-by:"):
                powered_by = line[13:].strip()

        banner = status_line
        if server_header:
            banner = f"{banner} | Server: {server_header}"
            match = re.match(r"^([A-Za-z0-9_-]+)(?:/([0-9A-Za-z._-]+))?", server_header)
            if match:
                product = match.group(1)
                version = match.group(2)
        elif "HTTP/" in status_line:
            product = "Generic HTTP Server"

        if powered_by:
            banner = f"{banner} | X-Powered-By: {powered_by}"

        confidence = (
            ObservationConfidence.HIGH if (product and version) else ObservationConfidence.MEDIUM
        )

        return ServiceFingerprint(
            service_name="http",
            transport_protocol=TransportProtocol.TCP,
            product=product,
            version=version,
            confidence=confidence,
            banner_snippet=sanitize_banner(banner),
            probe_method="http_headers",
            limitations="Extracted from standard HTTP status and Server headers.",
            extra_metadata={
                "status_line": status_line,
                "server": server_header,
                "x_powered_by": powered_by,
            },
        )
