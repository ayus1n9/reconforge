"""Conservative database endpoint detection for Redis, MySQL, and PostgreSQL."""

import asyncio
import logging
import struct

from reconforge.core.enums import ObservationConfidence, TransportProtocol
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.fingerprinting.probes.base import (
    BaseServiceProbe,
    safe_close_writer,
    sanitize_banner,
)

logger = logging.getLogger("reconforge.probes.database")


class DatabaseProbe(BaseServiceProbe):
    """Safely identifies common database listener endpoints without executing privileged commands."""

    name: str = "database"
    default_ports = (6379, 3306, 5432)

    async def _probe_redis(self, ip: str, port: int, timeout: float) -> ServiceFingerprint | None:
        """Probe Redis using standard RESP PING command."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except Exception:
            return None

        try:
            writer.write(b"PING\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(512), timeout=timeout)
            text = raw.decode("latin-1", errors="replace")

            if text.startswith("+PONG") or "NOAUTH" in text or "ERR" in text:
                auth_req = "NOAUTH" in text
                banner = (
                    "Redis (Authentication Required)"
                    if auth_req
                    else "Redis (Unauthenticated Access)"
                )
                return ServiceFingerprint(
                    service_name="redis",
                    transport_protocol=TransportProtocol.TCP,
                    product="Redis",
                    version=None,
                    confidence=ObservationConfidence.HIGH,
                    banner_snippet=sanitize_banner(banner),
                    probe_method="redis_resp_ping",
                    limitations="Identified via Redis Serialization Protocol PING; no database keys accessed.",
                    extra_metadata={"requires_auth": auth_req},
                )
        except Exception:
            return None
        finally:
            await safe_close_writer(writer)
        return None

    async def _probe_mysql(self, ip: str, port: int, timeout: float) -> ServiceFingerprint | None:
        """Inspect initial MySQL/MariaDB server handshake packet."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except Exception:
            return None

        try:
            raw = await asyncio.wait_for(reader.read(512), timeout=timeout)
            if len(raw) >= 5:
                proto_ver = raw[4]
                if proto_ver in (9, 10):
                    null_idx = raw.find(b"\x00", 5)
                    if null_idx > 5:
                        ver_str = raw[5:null_idx].decode("latin-1", errors="replace")
                        product = "MariaDB" if "mariadb" in ver_str.lower() else "MySQL"
                        return ServiceFingerprint(
                            service_name="mysql",
                            transport_protocol=TransportProtocol.TCP,
                            product=product,
                            version=ver_str,
                            confidence=ObservationConfidence.HIGH,
                            banner_snippet=sanitize_banner(f"{product} {ver_str}"),
                            probe_method="mysql_handshake_packet",
                            limitations="Extracted from initial server handshake packet without user authentication.",
                        )
        except Exception:
            return None
        finally:
            await safe_close_writer(writer)
        return None

    async def _probe_postgres(
        self, ip: str, port: int, timeout: float
    ) -> ServiceFingerprint | None:
        """Probe PostgreSQL listener using standard SSLRequest packet."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
        except Exception:
            return None

        try:
            ssl_req = struct.pack("!II", 8, 80877103)
            writer.write(ssl_req)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(1), timeout=timeout)
            if resp in (b"S", b"N"):
                ssl_supported = resp == b"S"
                banner = f"PostgreSQL (SSL Supported: {ssl_supported})"
                return ServiceFingerprint(
                    service_name="postgresql",
                    transport_protocol=TransportProtocol.TCP,
                    product="PostgreSQL",
                    version=None,
                    confidence=ObservationConfidence.HIGH,
                    banner_snippet=sanitize_banner(banner),
                    probe_method="postgres_ssl_request",
                    limitations="Identified via standard PostgreSQL SSLRequest handshake without authentication.",
                    extra_metadata={"ssl_supported": ssl_supported},
                )
        except Exception:
            return None
        finally:
            await safe_close_writer(writer)
        return None

    async def probe(self, ip: str, port: int, timeout: float = 3.0) -> ServiceFingerprint | None:
        if port == 6379:
            return await self._probe_redis(ip, port, timeout)
        if port == 3306:
            return await self._probe_mysql(ip, port, timeout)
        if port == 5432:
            return await self._probe_postgres(ip, port, timeout)

        for probe_fn in (self._probe_redis, self._probe_mysql, self._probe_postgres):
            res = await probe_fn(ip, port, timeout)
            if res:
                return res
        return None
