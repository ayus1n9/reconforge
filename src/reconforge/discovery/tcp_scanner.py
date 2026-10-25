"""Asynchronous TCP connect scanner with bounded concurrency, rate limiting, and service fingerprinting."""

import asyncio
import errno
import logging
import time
from collections.abc import Callable, Sequence

from reconforge.core.enums import PortState, ScanStatus, TransportProtocol
from reconforge.core.exceptions import ScopeViolationError
from reconforge.core.models import (
    HostDiscoveryResult,
    PortObservation,
    ScanConfig,
    ScanProgress,
    ScanSummary,
    ScanTarget,
)
from reconforge.core.scope import ScopeManager
from reconforge.discovery.rate_limiter import AsyncTokenBucketRateLimiter
from reconforge.fingerprinting.nmap_adapter import NmapAdapter
from reconforge.fingerprinting.service_detector import ServiceDetector

logger = logging.getLogger("reconforge.scanner")


class AsyncTCPScanner:
    """High-performance, resource-bounded asynchronous TCP connect scanner.

    Guarantees:
    - Bounded concurrency prevents file descriptor and memory exhaustion.
    - Token-bucket rate limiting enforces strict bandwidth/probe limits.
    - Every probe validates authorization against ScopeManager before opening a socket.
    - Full socket cleanup (no leaked file descriptors).
    - Responsive cancellation and deterministic progress reporting.
    - Optional non-intrusive service fingerprinting on open ports.
    """

    def __init__(
        self,
        scope_manager: ScopeManager,
        config: ScanConfig | None = None,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        service_detector: ServiceDetector | None = None,
        nmap_adapter: NmapAdapter | None = None,
    ):
        self.scope_manager = scope_manager
        self.config = config or ScanConfig()
        self.progress_callback = progress_callback
        self.rate_limiter = AsyncTokenBucketRateLimiter(self.config.rate_limit_per_second)
        self.semaphore = asyncio.Semaphore(self.config.concurrency)
        self.service_detector = service_detector or ServiceDetector()
        self.nmap_adapter = nmap_adapter or NmapAdapter()

        self._cancelled = False
        self._completed_probes = 0
        self._open_ports_count = 0
        self._total_probes = 0
        self._start_time: float | None = None
        self._active_tasks: set[asyncio.Task] = set()

    def cancel(self) -> None:
        """Signal the scanner to immediately cease probing and terminate pending tasks."""
        self._cancelled = True
        logger.info("Scan cancellation requested. Aborting active tasks.")
        for task in list(self._active_tasks):
            if not task.done():
                task.cancel()

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    async def scan_single_port(
        self,
        target: ScanTarget,
        port: int,
    ) -> PortObservation:
        """Probe a single TCP port using a 3-way handshake connect probe.

        Enforces scope validation, rate limiting, and bounded concurrency.
        """
        if self._cancelled:
            return PortObservation(
                target_ip=target.ip,
                hostname=target.hostname,
                port=port,
                state=PortState.NOT_SCANNED,
                error_message="Scan cancelled before probe execution.",
            )

        # 1. Mandatory Pre-Flight Scope Authorization Check
        self.scope_manager.validate_target_and_port(target.ip, port)

        # 2. Rate Limiting Check
        await self.rate_limiter.acquire()

        # 3. Bounded Concurrency Check
        async with self.semaphore:
            if self._cancelled:
                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    state=PortState.NOT_SCANNED,
                    error_message="Scan cancelled while waiting for concurrency slot.",
                )

            start_t = time.monotonic()
            reader = None
            writer = None
            try:
                # Direct socket connect to PINNED IP (avoids DNS TOCTOU/rebinding)
                conn = asyncio.open_connection(
                    host=target.ip,
                    port=port,
                )
                reader, writer = await asyncio.wait_for(conn, timeout=self.config.timeout_seconds)
                elapsed_ms = (time.monotonic() - start_t) * 1000.0

                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.OPEN,
                    response_time_ms=round(elapsed_ms, 2),
                    source="internal_tcp_connect",
                )

            except TimeoutError:
                # Distinct from filtered: we did not receive an ICMP filter response
                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.TIMEOUT,
                    error_message=f"Connection attempt timed out after {self.config.timeout_seconds}s.",
                    source="internal_tcp_connect",
                )

            except (ConnectionRefusedError, ConnectionResetError) as err:
                # TCP RST received - port is closed
                elapsed_ms = (time.monotonic() - start_t) * 1000.0
                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.CLOSED,
                    response_time_ms=round(elapsed_ms, 2),
                    error_message=str(err),
                    source="internal_tcp_connect",
                )

            except OSError as err:
                err_code = err.errno
                if err_code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
                    state = PortState.UNREACHABLE
                elif err_code in (errno.EACCES, errno.EPERM):
                    state = PortState.FILTERED
                else:
                    state = PortState.ERROR

                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=state,
                    error_message=str(err),
                    source="internal_tcp_connect",
                )

            except asyncio.CancelledError:
                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.NOT_SCANNED,
                    error_message="Probe task was cancelled.",
                    source="internal_tcp_connect",
                )

            except Exception as err:
                return PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.ERROR,
                    error_message=f"Unexpected exception: {type(err).__name__}: {err}",
                    source="internal_tcp_connect",
                )

            finally:
                # Guarantee clean socket closure
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception as close_err:
                        logger.debug("Error during socket close: %s", close_err)

    async def check_host_alive(self, target: ScanTarget) -> HostDiscoveryResult:
        """Conservative host liveness check against configured discovery ports.

        Does not assume host is offline simply if a port fails.
        """
        start_t = time.monotonic()
        for port in self.config.host_discovery_ports:
            if not self.scope_manager.is_port_allowed(port):
                continue
            obs = await self.scan_single_port(target, port)
            if obs.state == PortState.OPEN:
                return HostDiscoveryResult(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    is_alive=True,
                    responding_port=port,
                    latency_ms=obs.response_time_ms,
                    method="tcp_syn_ack",
                )
            if obs.state == PortState.CLOSED:
                # Receiving a RST proves the host IP is active and routing packets!
                return HostDiscoveryResult(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    is_alive=True,
                    responding_port=port,
                    latency_ms=obs.response_time_ms,
                    method="tcp_rst",
                )

        latency = (time.monotonic() - start_t) * 1000.0
        return HostDiscoveryResult(
            target_ip=target.ip,
            hostname=target.hostname,
            is_alive=False,
            latency_ms=round(latency, 2),
            method="tcp_probe_inconclusive",
        )

    async def scan_targets(
        self,
        targets: Sequence[ScanTarget],
        ports: Sequence[int],
    ) -> tuple[list[PortObservation], ScanSummary]:
        """Execute an asynchronous scan across multiple targets and ports.

        Maintains bounded concurrency, telemetry progress reporting, and optional service fingerprinting.
        """
        self._cancelled = False
        self._completed_probes = 0
        self._open_ports_count = 0
        self._start_time = time.monotonic()

        target_list = list(targets)
        port_list = list(ports)
        self._total_probes = len(target_list) * len(port_list)

        results: list[PortObservation] = []
        counts = {
            PortState.OPEN: 0,
            PortState.CLOSED: 0,
            PortState.FILTERED: 0,
            PortState.TIMEOUT: 0,
            PortState.UNREACHABLE: 0,
            PortState.ERROR: 0,
            PortState.NOT_SCANNED: 0,
        }

        # Filter active targets if host discovery is enabled
        active_targets = target_list
        if not self.config.skip_host_discovery:
            logger.info("Performing host discovery on %d targets...", len(target_list))
            verified_active = []
            for t in target_list:
                alive_res = await self.check_host_alive(t)
                if alive_res.is_alive:
                    verified_active.append(t)
                else:
                    logger.debug("Host %s not responding to discovery probes.", t.ip)
            active_targets = verified_active
            self._total_probes = len(active_targets) * len(port_list)

        # Worker coroutine for each target-port pair
        async def probe_worker(target: ScanTarget, port: int) -> PortObservation:
            try:
                obs = await self.scan_single_port(target, port)
            except ScopeViolationError as e:
                obs = PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    state=PortState.ERROR,
                    error_message=f"Scope violation: {e}",
                )
            except Exception as e:
                obs = PortObservation(
                    target_ip=target.ip,
                    hostname=target.hostname,
                    port=port,
                    state=PortState.ERROR,
                    error_message=f"Scanner error: {e}",
                )

            # Update telemetry
            self._completed_probes += 1
            if obs.state == PortState.OPEN:
                self._open_ports_count += 1
            counts[obs.state] = counts.get(obs.state, 0) + 1

            if self.progress_callback and self._start_time:
                elapsed = time.monotonic() - self._start_time
                progress = ScanProgress(
                    total_targets=len(active_targets),
                    total_probes=self._total_probes,
                    completed_probes=self._completed_probes,
                    open_ports_count=self._open_ports_count,
                    elapsed_seconds=round(elapsed, 2),
                )
                try:
                    self.progress_callback(progress)
                except Exception as cb_err:
                    logger.debug("Error in progress callback: %s", cb_err)

            return obs

        # Schedule port discovery tasks
        tasks: list[asyncio.Task[PortObservation]] = []
        for t in active_targets:
            for p in port_list:
                task = asyncio.create_task(probe_worker(t, p))
                tasks.append(task)
                self._active_tasks.add(task)
                task.add_done_callback(self._active_tasks.discard)

        if tasks:
            done_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in done_results:
                if isinstance(res, PortObservation):
                    results.append(res)
                elif isinstance(res, asyncio.CancelledError):
                    counts[PortState.NOT_SCANNED] += 1
                else:
                    logger.error("Unexpected worker gather exception: %s", res)
                    counts[PortState.ERROR] += 1

        # Phase 2: Service Fingerprinting on Discovered Open Ports
        if not self._cancelled and self.config.fingerprint_services:
            open_observations = [r for r in results if r.state == PortState.OPEN]
            if open_observations:
                if self.config.use_nmap and self.nmap_adapter.is_available():
                    logger.info("Running Nmap adapter for %d open ports...", len(open_observations))
                    try:
                        unique_ips = list({obs.target_ip for obs in open_observations})
                        unique_ports = list({obs.port for obs in open_observations})
                        nmap_results = await self.nmap_adapter.scan_services(
                            targets=unique_ips,
                            ports=unique_ports,
                            timeout=self.config.timeout_seconds * len(unique_ports) + 10.0,
                        )
                        nmap_map = {(ip, p): fp for ip, p, fp in nmap_results}
                        for obs in open_observations:
                            if (obs.target_ip, obs.port) in nmap_map:
                                obs.service = nmap_map[(obs.target_ip, obs.port)]
                    except Exception as err:
                        logger.warning(
                            "Nmap adapter failed, falling back to internal probes: %s", err
                        )

                # For any open observation without a service yet, run internal ServiceDetector
                for obs in open_observations:
                    if obs.service is None:
                        obs.service = await self.service_detector.identify_service(
                            ip=obs.target_ip,
                            port=obs.port,
                            timeout=self.config.timeout_seconds,
                        )

        duration = time.monotonic() - self._start_time
        status = ScanStatus.CANCELLED if self._cancelled else ScanStatus.COMPLETED

        summary = ScanSummary(
            targets_assessed=len(active_targets),
            probes_attempted=self._completed_probes,
            open_count=counts[PortState.OPEN],
            closed_count=counts[PortState.CLOSED],
            filtered_count=counts[PortState.FILTERED],
            timeout_count=counts[PortState.TIMEOUT],
            unreachable_count=counts[PortState.UNREACHABLE],
            error_count=counts[PortState.ERROR] + counts[PortState.NOT_SCANNED],
            duration_seconds=round(duration, 2),
            status=status,
        )

        return results, summary
