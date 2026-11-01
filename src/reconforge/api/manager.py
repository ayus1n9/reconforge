"""Asynchronous background execution and state manager for network discovery scans."""

import asyncio
import logging
from datetime import UTC, datetime

from reconforge import __version__
from reconforge.assessment.engine import ExposureEngine
from reconforge.core.models import ScanConfig, ScanProgress, ScanTarget, TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.discovery.dns_resolver import DNSResolver
from reconforge.discovery.tcp_scanner import AsyncTCPScanner
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.correlator import VulnerabilityCorrelator
from reconforge.inventory.repository import AssetRepository
from reconforge.scoring.calculator import AttackSurfaceCalculator
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord
from reconforge.utils.network import parse_ports

logger = logging.getLogger("reconforge.api.manager")


class ScanExecutionManager:
    """Manages lifecycle, background tasks, live progress, and cancellation of scans."""

    def __init__(self):
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._scanners: dict[str, AsyncTCPScanner] = {}
        self._progress: dict[str, ScanProgress] = {}
        self._start_times: dict[str, float] = {}

    def is_running(self, assessment_id: str) -> bool:
        """Check if an assessment scan is actively running."""
        task = self._active_tasks.get(assessment_id)
        return task is not None and not task.done()

    def get_progress(self, assessment_id: str) -> ScanProgress | None:
        """Get the latest recorded progress for an active scan."""
        return self._progress.get(assessment_id)

    def get_elapsed_seconds(self, assessment_id: str) -> float:
        """Get elapsed seconds since scan start."""
        start = self._start_times.get(assessment_id)
        if start:
            import time

            return time.monotonic() - start
        return 0.0

    async def start_scan(
        self,
        assessment_id: str,
        name: str,
        scope: TargetScope,
        config: ScanConfig,
        assess: bool,
        correlate_cves: bool,
        db_mgr: DatabaseManager,
    ) -> None:
        """Queue and launch asynchronous background scan task."""
        loop = asyncio.get_running_loop()
        task = loop.create_task(
            self._execute_scan(
                assessment_id=assessment_id,
                name=name,
                scope=scope,
                config=config,
                assess=assess,
                correlate_cves=correlate_cves,
                db_mgr=db_mgr,
            )
        )
        self._active_tasks[assessment_id] = task
        import time

        self._start_times[assessment_id] = time.monotonic()

    async def _execute_scan(
        self,
        assessment_id: str,
        name: str,
        scope: TargetScope,
        config: ScanConfig,
        assess: bool,
        correlate_cves: bool,
        db_mgr: DatabaseManager,
    ) -> None:
        """Execute the end-to-end scanning and analysis pipeline."""
        repo = AssetRepository(db_mgr)
        scope_manager = ScopeManager(scope)

        try:
            parsed_ports = parse_ports(scope.allowed_ports)
            scan_targets: list[ScanTarget] = scope_manager.expand_static_targets()

            if scope_manager.allowed_hostnames:
                resolver = DNSResolver(
                    scope_manager=scope_manager, timeout_seconds=config.timeout_seconds
                )
                resolved = await resolver.resolve_all_scoped_hostnames()
                scan_targets.extend(resolved)

            scanner = AsyncTCPScanner(scope_manager=scope_manager, config=config)
            self._scanners[assessment_id] = scanner

            def on_progress(p: ScanProgress) -> None:
                self._progress[assessment_id] = p

            scanner.progress_callback = on_progress

            # Update DB record to running
            with db_mgr.session() as session:
                from sqlalchemy import select

                stmt = select(AssessmentRecord).where(AssessmentRecord.id == assessment_id)
                record = session.execute(stmt).scalars().first()
                if record:
                    record.status = "running"
                    record.coverage_metrics = {
                        "total_targets": len(scan_targets),
                        "ports_specified": len(parsed_ports),
                    }

            observations, summary = await scanner.scan_targets(scan_targets, parsed_ports)

            if scanner._cancelled or summary.status == "cancelled":
                with db_mgr.session() as session:
                    from sqlalchemy import select

                    stmt = select(AssessmentRecord).where(AssessmentRecord.id == assessment_id)
                    record = session.execute(stmt).scalars().first()
                    if record:
                        record.status = "cancelled"
                        record.end_time = datetime.now(UTC)
                return

            # Record observations and update assessment
            repo.record_scan_results(
                assessment_id=assessment_id,
                scope_config=scope.model_dump(),
                scanner_version=__version__,
                observations=observations,
                summary=summary,
                assessment_name=name,
            )

            # Rule-based exposure assessment
            if assess:
                exposure_engine = ExposureEngine()
                exposure_engine.evaluate_assessment(assessment_id, db_mgr, persist=True)

            # Offline CVE correlation
            if correlate_cves:
                correlator = VulnerabilityCorrelator(cache=VulnerabilityCache(db_mgr))
                correlator.correlate_assessment_services(
                    assessment_id, repo, record_findings=True, online=False
                )

            # Attack-surface posture calculation
            if assess or correlate_cves:
                try:
                    calculator = AttackSurfaceCalculator()
                    calculator.calculate_assessment_posture(assessment_id, repo)
                except Exception as p_err:
                    logger.debug("Posture calculation error in API scan: %s", p_err)

            # Mark assessment completed
            with db_mgr.session() as session:
                from sqlalchemy import select

                stmt = select(AssessmentRecord).where(AssessmentRecord.id == assessment_id)
                record = session.execute(stmt).scalars().first()
                if record:
                    record.status = "completed"
                    record.end_time = datetime.now(UTC)

        except asyncio.CancelledError:
            logger.info("Scan task for assessment %s was cancelled.", assessment_id)
            with db_mgr.session() as session:
                from sqlalchemy import select

                stmt = select(AssessmentRecord).where(AssessmentRecord.id == assessment_id)
                record = session.execute(stmt).scalars().first()
                if record:
                    record.status = "cancelled"
                    record.end_time = datetime.now(UTC)
        except Exception as err:
            logger.exception("Scan execution failed for assessment %s: %s", assessment_id, err)
            with db_mgr.session() as session:
                from sqlalchemy import select

                stmt = select(AssessmentRecord).where(AssessmentRecord.id == assessment_id)
                record = session.execute(stmt).scalars().first()
                if record:
                    record.status = "failed"
                    record.error_summary = str(err)
                    record.end_time = datetime.now(UTC)
        finally:
            self._active_tasks.pop(assessment_id, None)
            self._scanners.pop(assessment_id, None)
            self._progress.pop(assessment_id, None)
            self._start_times.pop(assessment_id, None)

    async def cancel_scan(self, assessment_id: str, db_mgr: DatabaseManager) -> bool:
        """Cancel a running scan cooperatively and update database status."""
        scanner = self._scanners.get(assessment_id)
        if scanner:
            scanner.cancel()

        task = self._active_tasks.get(assessment_id)
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            except (asyncio.CancelledError, TimeoutError, Exception):
                pass

        with db_mgr.session() as session:
            from sqlalchemy import select

            stmt = select(AssessmentRecord).where(AssessmentRecord.id == assessment_id)
            record = session.execute(stmt).scalars().first()
            if record and record.status in ("pending", "running"):
                record.status = "cancelled"
                record.end_time = datetime.now(UTC)
                return True
        return False

    async def cancel_all(self, db_mgr: DatabaseManager) -> None:
        """Cancel all active scans during application shutdown."""
        active_ids = list(self._active_tasks.keys())
        for a_id in active_ids:
            await self.cancel_scan(a_id, db_mgr)
