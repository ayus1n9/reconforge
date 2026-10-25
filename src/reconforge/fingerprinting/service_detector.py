"""Central service detection and protocol fingerprinting orchestrator."""

import logging
from collections.abc import Sequence

from reconforge.core.enums import ObservationConfidence, TransportProtocol
from reconforge.fingerprinting.models import ServiceFingerprint
from reconforge.fingerprinting.probes.base import BaseServiceProbe
from reconforge.fingerprinting.probes.database_probe import DatabaseProbe
from reconforge.fingerprinting.probes.ftp_probe import FTPProbe
from reconforge.fingerprinting.probes.http_probe import HTTPProbe
from reconforge.fingerprinting.probes.smtp_probe import SMTPProbe
from reconforge.fingerprinting.probes.ssh_probe import SSHProbe
from reconforge.fingerprinting.probes.tls_probe import TLSProbe

logger = logging.getLogger("reconforge.fingerprinting")


class ServiceDetector:
    """Orchestrates non-intrusive protocol probes to accurately identify network services.

    Avoids assuming service identity based merely on port numbers (e.g. port 443 does not guarantee HTTPS).
    """

    def __init__(self, probes: Sequence[BaseServiceProbe] | None = None):
        if probes is not None:
            self.probes = list(probes)
        else:
            self.probes = [
                TLSProbe(),
                HTTPProbe(),
                SSHProbe(),
                SMTPProbe(),
                FTPProbe(),
                DatabaseProbe(),
            ]

    def _prioritize_probes(self, port: int) -> list[BaseServiceProbe]:
        """Order probes based on typical default port associations to optimize detection speed."""
        matched: list[BaseServiceProbe] = []
        others: list[BaseServiceProbe] = []

        for p in self.probes:
            if port in p.default_ports:
                matched.append(p)
            else:
                others.append(p)

        return matched + others

    async def identify_service(
        self, ip: str, port: int, timeout: float = 3.0
    ) -> ServiceFingerprint:
        """Run ordered probes against an open port to produce an evidence-backed ServiceFingerprint."""
        ordered_probes = self._prioritize_probes(port)

        for probe in ordered_probes:
            try:
                fp = await probe.probe(ip, port, timeout=timeout)
                if fp:
                    logger.debug(
                        "Identified %s:%d as '%s' via %s (confidence: %s)",
                        ip,
                        port,
                        fp.service_name,
                        fp.probe_method,
                        fp.confidence.value,
                    )
                    return fp
            except Exception as err:
                logger.debug("Probe %s error on %s:%d: %s", probe.name, ip, port, err)

        # Inconclusive / Unknown service
        return ServiceFingerprint(
            service_name="unknown",
            transport_protocol=TransportProtocol.TCP,
            product=None,
            version=None,
            confidence=ObservationConfidence.UNKNOWN,
            banner_snippet=None,
            probe_method="probes_exhausted",
            limitations="TCP port is open, but endpoint did not match known application protocol signatures.",
            source="reconforge_internal",
        )
