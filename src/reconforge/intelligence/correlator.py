"""Vulnerability correlation engine mapping service banners to calibrated CVE intelligence."""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from reconforge.core.enums import FindingState, SeverityLevel
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.cpe import CPE
from reconforge.intelligence.models import CVECorrelationResult, CVEItem, CVEMatchLevel
from reconforge.intelligence.nvd_client import AsyncNVDClient
from reconforge.intelligence.version_matcher import evaluate_cve_match
from reconforge.inventory.repository import AssetRepository
from reconforge.storage.models import AssessmentRecord, FindingRecord, ServiceRecord

logger = logging.getLogger("reconforge.intelligence.correlator")


class VulnerabilityCorrelator:
    """Correlates observed network services with vulnerability intelligence and assigns calibrated confidence levels."""

    def __init__(
        self,
        cache: VulnerabilityCache | None = None,
        nvd_client: AsyncNVDClient | None = None,
        min_severity: SeverityLevel = SeverityLevel.LOW,
    ):
        self.cache = cache or VulnerabilityCache()
        self.nvd = nvd_client or AsyncNVDClient(cache=self.cache, offline_mode=True)
        self.min_severity = min_severity

    def derive_service_cpe(
        self,
        service_name: str,
        product: str | None = None,
        version: str | None = None,
        cpe_candidate: str | None = None,
    ) -> CPE:
        """Parse an existing candidate CPE or derive standard CPE 2.3 from service attributes."""
        if cpe_candidate and cpe_candidate.startswith("cpe:"):
            try:
                return CPE.from_string(cpe_candidate)
            except Exception as err:
                logger.debug("Failed to parse candidate CPE string '%s': %s", cpe_candidate, err)
        return CPE.from_service(service_name=service_name, product=product, version=version)

    async def correlate_service_async(
        self,
        service_name: str,
        product: str | None = None,
        version: str | None = None,
        banner: str | None = None,
        cpe_candidate: str | None = None,
        online: bool = False,
    ) -> list[CVECorrelationResult]:
        """Correlate a single service against vulnerability intelligence asynchronously."""
        cpe = self.derive_service_cpe(service_name, product, version, cpe_candidate)
        results: list[CVECorrelationResult] = []

        # Find candidate CVEs matching vendor or product
        search_terms = [cpe.product, cpe.vendor]
        candidates: dict[str, CVEItem] = {}

        for term in search_terms:
            if not term or term == "*":
                continue
            # Search cache
            cached_items = self.cache.search_cves(cpe_product=term)
            for item in cached_items:
                candidates[item.cve_id] = item

            # If online search requested and not found
            if online and not self.nvd.offline_mode:
                online_items = await self.nvd.search_by_cpe(cpe.to_cpe23())
                for item in online_items:
                    candidates[item.cve_id] = item

        for cve in candidates.values():
            # Check if CPE product and vendor match precisely
            matched_product_cpe = False
            for affected in cve.affected_cpes:
                try:
                    aff_cpe = CPE.from_string(affected)
                    vendor_match = (
                        aff_cpe.vendor == "*" or cpe.vendor == "*" or aff_cpe.vendor == cpe.vendor
                    )
                    product_match = (
                        aff_cpe.product == "*"
                        or cpe.product == "*"
                        or aff_cpe.product == cpe.product
                        or aff_cpe.product in cpe.product
                        or cpe.product in aff_cpe.product
                    )
                    if vendor_match and product_match:
                        matched_product_cpe = True
                        break
                except Exception:
                    if cpe.product.lower() in affected.lower():
                        matched_product_cpe = True
                        break

            if not matched_product_cpe:
                continue

            matched, match_level, rationale = evaluate_cve_match(version, banner, cve)
            if matched:
                remediation = f"Upgrade {cpe.product} to a patched release addressing {cve.cve_id}."
                if cve.references:
                    remediation += f" Consult vendor advisory: {cve.references[0]}"

                results.append(
                    CVECorrelationResult(
                        cve=cve,
                        match_level=match_level,
                        matched_cpe=cpe.to_cpe23(),
                        matched_version=version,
                        evidence_rationale=rationale,
                        remediation=remediation,
                    )
                )

        return results

    def correlate_service(
        self,
        service_name: str,
        product: str | None = None,
        version: str | None = None,
        banner: str | None = None,
        cpe_candidate: str | None = None,
        online: bool = False,
    ) -> list[CVECorrelationResult]:
        """Synchronous wrapper for correlating a single service."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If in an active event loop, run in thread or create task
            coro = self.correlate_service_async(
                service_name, product, version, banner, cpe_candidate, online
            )
            # Create a separate loop in a thread to run synchronously without blocking
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return asyncio.run(
                self.correlate_service_async(
                    service_name, product, version, banner, cpe_candidate, online
                )
            )

    def correlate_assessment_services(
        self,
        assessment_id: str,
        repository: AssetRepository,
        record_findings: bool = True,
        online: bool = False,
    ) -> dict[str, list[CVECorrelationResult]]:
        """Correlate all services observed during an assessment and record findings if requested.

        Returns:
            Dictionary mapping service_id to list of CVECorrelationResult items.
        """
        correlation_map: dict[str, list[CVECorrelationResult]] = {}
        severity_priority_map = {
            SeverityLevel.CRITICAL: "P1",
            SeverityLevel.HIGH: "P2",
            SeverityLevel.MEDIUM: "P3",
            SeverityLevel.LOW: "P4",
            SeverityLevel.INFORMATIONAL: "P5",
        }

        with repository.db.session() as session:
            # Locate assessment and eager-load findings
            stmt = select(AssessmentRecord).where(
                (AssessmentRecord.id == assessment_id)
                | (AssessmentRecord.id.startswith(assessment_id))
            )
            assessment = session.execute(stmt).scalar_one_or_none()
            if not assessment:
                logger.error("Assessment '%s' not found for CVE correlation", assessment_id)
                return {}

            # Query all services across assets
            services = session.execute(select(ServiceRecord)).scalars().all()
            for service in services:
                results = self.correlate_service(
                    service_name=service.service_name,
                    product=service.product,
                    version=service.version,
                    banner=service.banner_snippet,
                    cpe_candidate=service.cpe_candidate,
                    online=online,
                )
                if not results:
                    continue

                correlation_map[service.id] = results

                if record_findings:
                    for res in results:
                        rule_id = f"cve-{res.cve.cve_id.lower()}"
                        # Check existing finding
                        existing = session.execute(
                            select(FindingRecord).where(
                                FindingRecord.assessment_id == assessment.id,
                                FindingRecord.service_id == service.id,
                                FindingRecord.rule_id == rule_id,
                            )
                        ).scalar_one_or_none()

                        # Determine finding state based on calibrated match level
                        if res.match_level == CVEMatchLevel.STRONG_CANDIDATE:
                            finding_state = FindingState.POTENTIAL_VULNERABILITY
                        elif res.match_level == CVEMatchLevel.MANUAL_VERIFICATION_REQUIRED:
                            finding_state = FindingState.NEEDS_REVIEW
                        elif res.match_level == CVEMatchLevel.POSSIBLE_MATCH:
                            finding_state = FindingState.POTENTIAL_EXPOSURE
                        else:
                            finding_state = FindingState.INFORMATIONAL

                        evidence_payload: dict[str, Any] = {
                            "cve_id": res.cve.cve_id,
                            "cvss_v3_score": res.cve.cvss_v3_score,
                            "cvss_v3_vector": res.cve.cvss_v3_vector,
                            "match_level": res.match_level.value,
                            "matched_cpe": res.matched_cpe,
                            "matched_version": res.matched_version,
                            "evidence_rationale": res.evidence_rationale,
                            "is_known_exploited": res.cve.is_known_exploited,
                            "references": res.cve.references,
                        }

                        if not existing:
                            record = FindingRecord(
                                id=str(uuid4()),
                                assessment_id=assessment.id,
                                asset_id=service.asset_id,
                                service_id=service.id,
                                rule_id=rule_id,
                                cve_id=res.cve.cve_id,
                                title=f"{res.cve.cve_id}: {res.cve.description[:90]}...",
                                description=res.cve.description,
                                severity=res.cve.severity.value,
                                priority=severity_priority_map.get(res.cve.severity, "P3"),
                                state=finding_state.value,
                                evidence=evidence_payload,
                                remediation_guidance=res.remediation,
                                created_at=datetime.now(UTC),
                                updated_at=datetime.now(UTC),
                            )
                            session.add(record)
                        else:
                            existing.evidence = evidence_payload
                            existing.state = finding_state.value
                            existing.updated_at = datetime.now(UTC)

            session.commit()

        return correlation_map
