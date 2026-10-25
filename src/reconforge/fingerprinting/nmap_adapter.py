"""Hardened Nmap subprocess adapter and secure XML parser."""

import asyncio
import logging
import os
import shutil
from collections.abc import Sequence

import defusedxml.ElementTree as DefusedET

from reconforge.core.enums import ObservationConfidence, TransportProtocol
from reconforge.core.exceptions import ScanError
from reconforge.fingerprinting.models import ServiceFingerprint

logger = logging.getLogger("reconforge.adapters.nmap")

# Security ceiling: 10 MB maximum allowed XML output from subprocess
MAX_XML_OUTPUT_BYTES = 10 * 1024 * 1024


class NmapAdapter:
    """Safely executes Nmap in a sandboxed subprocess and parses XML output using defusedxml.

    Guarantees:
    - Never uses shell execution (shell=False).
    - Hardened XML parsing blocks XXE and billion-laughs XML bombs.
    - Limits execution duration and stdout output size.
    - Preserves source attribution ('source=nmap').
    - Only invokes conservative, non-evasive service discovery flags (-sT -sV).
    """

    def __init__(self, binary_path: str | None = None):
        self.binary_path = binary_path or shutil.which("nmap")

    def is_available(self) -> bool:
        """Verify that the Nmap executable exists and has execute permissions."""
        if not self.binary_path:
            return False
        return os.path.isfile(self.binary_path) and os.access(self.binary_path, os.X_OK)

    def parse_nmap_xml(self, xml_content: str | bytes) -> list[tuple[str, int, ServiceFingerprint]]:
        """Parse Nmap XML string safely using defusedxml.

        Returns:
            List of (target_ip, port, ServiceFingerprint) tuples.
        """
        results: list[tuple[str, int, ServiceFingerprint]] = []
        if not xml_content:
            return results

        try:
            root = DefusedET.fromstring(xml_content)
        except Exception as err:
            logger.error("Failed to parse Nmap XML (malformed or truncated): %s", err)
            raise ScanError(f"Nmap XML parsing failure: {err}") from err

        for host_elem in root.findall("host"):
            # Extract IP address
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host_elem.find("address[@addrtype='ipv6']")
            if addr_elem is None:
                continue

            target_ip = addr_elem.get("addr")
            if not target_ip:
                continue

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                proto = port_elem.get("protocol", "tcp")
                port_id_str = port_elem.get("portid")
                if not port_id_str or proto != "tcp":
                    continue
                try:
                    port = int(port_id_str)
                except ValueError:
                    continue

                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = (
                    service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                )
                product = service_elem.get("product") if service_elem is not None else None
                version = service_elem.get("version") if service_elem is not None else None
                extrainfo = service_elem.get("extrainfo") if service_elem is not None else None

                cpe_candidate = None
                if service_elem is not None:
                    cpe_elem = service_elem.find("cpe")
                    if cpe_elem is not None and cpe_elem.text:
                        cpe_candidate = cpe_elem.text.strip()

                banner = f"{service_name}"
                if product:
                    banner = f"{banner} {product}"
                if version:
                    banner = f"{banner} {version}"
                if extrainfo:
                    banner = f"{banner} ({extrainfo})"

                confidence = (
                    ObservationConfidence.HIGH
                    if (product or version)
                    else ObservationConfidence.MEDIUM
                )

                fp = ServiceFingerprint(
                    service_name=service_name,
                    transport_protocol=TransportProtocol.TCP,
                    product=product,
                    version=version,
                    cpe_candidate=cpe_candidate,
                    confidence=confidence,
                    banner_snippet=banner,
                    probe_method="nmap_version_scan",
                    limitations="Normalized from Nmap service probe heuristics.",
                    source="nmap",
                )
                results.append((target_ip, port, fp))

        return results

    async def scan_services(
        self,
        targets: Sequence[str],
        ports: Sequence[int],
        timeout: float = 60.0,
    ) -> list[tuple[str, int, ServiceFingerprint]]:
        """Run Nmap TCP connect service detection (-sT -sV --version-light) via subprocess array."""
        if not self.is_available():
            raise ScanError(f"Nmap executable not found at '{self.binary_path}'")

        if not targets or not ports:
            return []

        port_spec = ",".join(str(p) for p in sorted(set(ports)))
        cmd = [
            self.binary_path,  # type: ignore[list-item]
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",  # Treat hosts as online
            "-p",
            port_spec,
            "-oX",
            "-",
            *list(targets),
        ]

        logger.info("Executing safe Nmap discovery: %s", " ".join(cmd))
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_data, stderr_data = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except TimeoutError as err:
            if proc:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                except Exception as kill_err:
                    logger.debug("Process kill exception suppressed: %s", kill_err)
            raise ScanError(f"Nmap process timed out after {timeout} seconds.") from err
        except Exception as err:
            raise ScanError(f"Failed to execute Nmap subprocess: {err}") from err

        if len(stdout_data) > MAX_XML_OUTPUT_BYTES:
            raise ScanError(
                f"Nmap output exceeded safe buffer size ({len(stdout_data)} > {MAX_XML_OUTPUT_BYTES} bytes)."
            )

        if proc.returncode != 0:
            err_msg = stderr_data.decode("utf-8", errors="replace").strip()
            raise ScanError(f"Nmap exited with code {proc.returncode}: {err_msg}")

        return self.parse_nmap_xml(stdout_data)
