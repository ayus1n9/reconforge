"""TLS/SSL handshake probe for certificate metadata and encrypted service inspection."""

import asyncio
import logging
import ssl
from datetime import UTC, datetime

from reconforge.core.enums import ObservationConfidence, TransportProtocol
from reconforge.fingerprinting.models import ServiceFingerprint, TLSMetadata
from reconforge.fingerprinting.probes.base import (
    BaseServiceProbe,
    safe_close_writer,
    sanitize_banner,
)

logger = logging.getLogger("reconforge.probes.tls")


def parse_ssl_date(date_str: str | None) -> datetime | None:
    """Parse standard OpenSSL date format (e.g. 'Apr 10 12:00:00 2026 GMT')."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=UTC)
    except Exception:
        return None


class TLSProbe(BaseServiceProbe):
    """Inspects TLS/SSL enabled endpoints, extracting certificate and cipher metadata."""

    name: str = "tls"
    default_ports = (443, 8443, 9443, 465, 993, 995, 636)

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create a permissive SSL context for assessment inspection.

        Disables certificate verification to allow inspection of self-signed and internal certificates.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def probe_tls_metadata(
        self, ip: str, port: int, timeout: float = 3.0
    ) -> tuple[TLSMetadata | None, asyncio.StreamReader | None, asyncio.StreamWriter | None]:
        """Attempt TLS handshake and return TLSMetadata and active streams if successful."""
        ctx = self._create_ssl_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=timeout,
            )
        except (TimeoutError, ssl.SSLError, OSError):
            return None, None, None
        except Exception as err:
            logger.debug("TLS connection error on %s:%d: %s", ip, port, err)
            return None, None, None

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if not ssl_obj:
                return None, reader, writer

            proto_version = ssl_obj.version()
            cipher_info = ssl_obj.cipher()
            cipher_name = cipher_info[0] if cipher_info else None

            cert = ssl_obj.getpeercert()
            subject_cn = None
            issuer_cn = None
            san_list: list[str] = []
            valid_from = None
            valid_until = None
            serial_number = cert.get("serialNumber") if cert else None

            if cert:
                for rdn in cert.get("subject", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            subject_cn = str(val)

                for rdn in cert.get("issuer", ()):
                    for key, val in rdn:
                        if key == "commonName":
                            issuer_cn = str(val)

                for typ, val in cert.get("subjectAltName", ()):
                    if typ in ("DNS", "IP Address"):
                        san_list.append(str(val))

                valid_from = parse_ssl_date(cert.get("notBefore"))
                valid_until = parse_ssl_date(cert.get("notAfter"))

            now = datetime.now(UTC)
            is_expired = bool(valid_until and valid_until < now)
            is_self_signed = bool(subject_cn and issuer_cn and subject_cn == issuer_cn)

            meta = TLSMetadata(
                protocol_version=proto_version,
                cipher_suite=cipher_name,
                subject_cn=subject_cn,
                issuer_cn=issuer_cn,
                subject_alt_names=san_list,
                valid_from=valid_from,
                valid_until=valid_until,
                is_expired=is_expired,
                is_self_signed=is_self_signed,
                serial_number=serial_number,
            )
            return meta, reader, writer
        except Exception as err:
            logger.debug("TLS metadata extraction error: %s", err)
            return None, reader, writer

    async def probe(self, ip: str, port: int, timeout: float = 3.0) -> ServiceFingerprint | None:
        meta, reader, writer = await self.probe_tls_metadata(ip, port, timeout=timeout)
        if not meta:
            await safe_close_writer(writer)
            return None

        # Try to send a safe minimal HTTP HEAD over TLS
        service_name = "ssl/unknown"
        product = None
        version = None
        banner = f"TLS {meta.protocol_version} Cipher: {meta.cipher_suite}"

        if reader and writer:
            try:
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: ReconForge/0.2.0\r\nConnection: close\r\n\r\n"
                writer.write(request.encode("ascii"))
                await writer.drain()

                response_bytes = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                if response_bytes:
                    text = response_bytes.decode("latin-1", errors="replace")
                    if "HTTP/" in text:
                        service_name = "https"
                        banner = sanitize_banner(text.split("\r\n")[0])
                        # Look for Server header
                        for line in text.split("\r\n"):
                            if line.lower().startswith("server:"):
                                server_val = line[7:].strip()
                                banner = f"{banner} | Server: {server_val}"
                                parts = server_val.split("/")
                                product = parts[0].strip()
                                if len(parts) > 1:
                                    version = parts[1].split()[0].strip()
                                break
            except Exception as comm_err:
                logger.debug("TLS HTTP head inspection failed: %s", comm_err)
            finally:
                await safe_close_writer(writer)

        return ServiceFingerprint(
            service_name=service_name,
            transport_protocol=TransportProtocol.TCP,
            product=product,
            version=version,
            confidence=ObservationConfidence.HIGH if product else ObservationConfidence.MEDIUM,
            banner_snippet=sanitize_banner(banner),
            tls_info=meta,
            probe_method="tls_handshake",
            limitations="TLS certificate verified; host data inspected via non-intrusive HEAD request.",
        )
