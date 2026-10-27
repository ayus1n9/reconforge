"""Repository pattern for managing normalized assets, services, and assessment records."""

import logging
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from reconforge.core.enums import PortState
from reconforge.core.models import PortObservation, ScanSummary
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, FindingRecord, ServiceRecord

logger = logging.getLogger("reconforge.inventory.repo")


class AssetRepository:
    """Manages transactional persistence for assets and services with referential integrity.

    Guarantees:
    - Assets are indexed by canonical IP address; different IPs sharing a hostname are NOT merged.
    - Timestamps (first_observed_at, last_observed_at) are tracked monotonically in UTC.
    - Service records maintain uniqueness on (asset_id, port, protocol).
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.db.init_db()

    def upsert_asset(
        self,
        ip_address: str,
        hostname: str | None = None,
        address_family: str = "ipv4",
        source: str = "tcp_scanner",
        criticality: str = "medium",
    ) -> AssetRecord:
        """Create or update an asset record, preserving identity separation."""
        with self.db.session() as session:
            stmt = select(AssetRecord).where(AssetRecord.ip_address == ip_address)
            asset = session.execute(stmt).scalar_one_or_none()

            now = datetime.now(UTC)
            if asset:
                asset.last_observed_at = now
                hostnames = list(asset.observed_hostnames or [])
                if hostname and hostname not in hostnames:
                    hostnames.append(hostname)
                    asset.observed_hostnames = hostnames

                sources = list(asset.discovery_sources or [])
                if source and source not in sources:
                    sources.append(source)
                    asset.discovery_sources = sources
            else:
                asset = AssetRecord(
                    id=str(uuid4()),
                    ip_address=ip_address,
                    address_family=address_family,
                    observed_hostnames=[hostname] if hostname else [],
                    discovery_sources=[source] if source else [],
                    criticality=criticality,
                    first_observed_at=now,
                    last_observed_at=now,
                )
                session.add(asset)

            session.flush()
            session.refresh(asset)
            return asset

    def upsert_service(
        self,
        asset_id: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "unknown",
        product: str | None = None,
        version: str | None = None,
        confidence: str = "unknown",
        banner_snippet: str | None = None,
        cpe_candidate: str | None = None,
        tls_metadata: dict | None = None,
        source: str = "reconforge_internal",
    ) -> ServiceRecord:
        """Create or update an observed network service linked to an asset."""
        with self.db.session() as session:
            stmt = select(ServiceRecord).where(
                ServiceRecord.asset_id == asset_id,
                ServiceRecord.port == port,
                ServiceRecord.protocol == protocol,
            )
            service = session.execute(stmt).scalar_one_or_none()

            now = datetime.now(UTC)
            if service:
                service.last_observed_at = now
                # Update identification if new observation provides product/version or non-unknown service
                if service_name != "unknown" or service.service_name == "unknown":
                    service.service_name = service_name
                if product:
                    service.product = product
                if version:
                    service.version = version
                if confidence != "unknown" or service.confidence == "unknown":
                    service.confidence = confidence
                if banner_snippet:
                    service.banner_snippet = banner_snippet
                if cpe_candidate:
                    service.cpe_candidate = cpe_candidate
                if tls_metadata:
                    service.tls_metadata = tls_metadata
                service.source = source
            else:
                service = ServiceRecord(
                    id=str(uuid4()),
                    asset_id=asset_id,
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    product=product,
                    version=version,
                    confidence=confidence,
                    banner_snippet=banner_snippet,
                    cpe_candidate=cpe_candidate,
                    tls_metadata=tls_metadata,
                    first_observed_at=now,
                    last_observed_at=now,
                    source=source,
                )
                session.add(service)

            session.flush()
            session.refresh(service)
            return service

    def record_scan_results(
        self,
        assessment_id: str,
        scope_config: dict,
        scanner_version: str,
        observations: list[PortObservation],
        summary: ScanSummary,
        assessment_name: str = "Assessment",
    ) -> AssessmentRecord:
        """Persist an assessment run along with all associated asset and service updates atomically."""
        with self.db.session() as session:
            now = datetime.now(UTC)
            assessment = AssessmentRecord(
                id=assessment_id,
                name=assessment_name,
                scope_config=scope_config,
                scanner_version=scanner_version,
                status=summary.status.value,
                start_time=now,
                end_time=now,
                coverage_metrics=summary.model_dump(),
                error_summary=None,
            )
            session.add(assessment)

            # Process observations
            for obs in observations:
                # Upsert asset
                stmt = select(AssetRecord).where(AssetRecord.ip_address == obs.target_ip)
                asset = session.execute(stmt).scalar_one_or_none()

                if asset:
                    asset.last_observed_at = now
                    hostnames = list(asset.observed_hostnames or [])
                    if obs.hostname and obs.hostname not in hostnames:
                        hostnames.append(obs.hostname)
                        asset.observed_hostnames = hostnames
                else:
                    asset = AssetRecord(
                        id=str(uuid4()),
                        ip_address=obs.target_ip,
                        address_family="ipv6" if ":" in obs.target_ip else "ipv4",
                        observed_hostnames=[obs.hostname] if obs.hostname else [],
                        discovery_sources=["tcp_scanner"],
                        first_observed_at=now,
                        last_observed_at=now,
                    )
                    session.add(asset)
                    session.flush()

                # If open, upsert service
                if obs.state == PortState.OPEN:
                    srv = obs.service
                    srv_name = srv.service_name if srv else "unknown"
                    product = srv.product if srv else None
                    version = srv.version if srv else None
                    conf = srv.confidence.value if srv else "unknown"
                    banner = srv.banner_snippet if srv else None
                    cpe = srv.cpe_candidate if srv else None
                    tls_meta = (
                        srv.tls_info.model_dump(mode="json") if (srv and srv.tls_info) else None
                    )
                    source = srv.source if srv else obs.source

                    srv_stmt = select(ServiceRecord).where(
                        ServiceRecord.asset_id == asset.id,
                        ServiceRecord.port == obs.port,
                        ServiceRecord.protocol == obs.protocol.value,
                    )
                    service = session.execute(srv_stmt).scalar_one_or_none()

                    if service:
                        service.last_observed_at = now
                        if srv_name != "unknown" or service.service_name == "unknown":
                            service.service_name = srv_name
                        if product:
                            service.product = product
                        if version:
                            service.version = version
                        if conf != "unknown" or service.confidence == "unknown":
                            service.confidence = conf
                        if banner:
                            service.banner_snippet = banner
                        if cpe:
                            service.cpe_candidate = cpe
                        if tls_meta:
                            service.tls_metadata = tls_meta
                    else:
                        service = ServiceRecord(
                            id=str(uuid4()),
                            asset_id=asset.id,
                            port=obs.port,
                            protocol=obs.protocol.value,
                            service_name=srv_name,
                            product=product,
                            version=version,
                            confidence=conf,
                            banner_snippet=banner,
                            cpe_candidate=cpe,
                            tls_metadata=tls_meta,
                            first_observed_at=now,
                            last_observed_at=now,
                            source=source,
                        )
                        session.add(service)

            session.flush()
            session.refresh(assessment)
            return assessment

    def get_asset(self, asset_id_or_ip: str) -> AssetRecord | None:
        """Retrieve asset with eager-loaded services by UUID, IP address, or UUID prefix."""
        with self.db.session() as session:
            stmt = (
                select(AssetRecord)
                .options(selectinload(AssetRecord.services))
                .where(
                    (AssetRecord.id == asset_id_or_ip)
                    | (AssetRecord.ip_address == asset_id_or_ip)
                    | (AssetRecord.id.startswith(asset_id_or_ip))
                )
            )
            return session.execute(stmt).scalars().first()

    def list_assets(self, limit: int = 50, offset: int = 0) -> list[AssetRecord]:
        """List assets with eager-loaded services ordered by last observation."""
        with self.db.session() as session:
            stmt = (
                select(AssetRecord)
                .options(selectinload(AssetRecord.services))
                .order_by(AssetRecord.last_observed_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(session.execute(stmt).scalars().all())

    def get_assessment(self, assessment_id: str) -> AssessmentRecord | None:
        """Retrieve assessment metadata by UUID or UUID prefix."""
        with self.db.session() as session:
            stmt = (
                select(AssessmentRecord)
                .options(selectinload(AssessmentRecord.findings))
                .where(
                    (AssessmentRecord.id == assessment_id)
                    | (AssessmentRecord.id.startswith(assessment_id))
                )
            )
            return session.execute(stmt).scalars().first()

    def list_assessments(self, limit: int = 50, offset: int = 0) -> list[AssessmentRecord]:
        """List assessment runs ordered by start time."""
        with self.db.session() as session:
            stmt = (
                select(AssessmentRecord)
                .order_by(AssessmentRecord.start_time.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(session.execute(stmt).scalars().all())

    def list_findings(
        self,
        assessment_id: str | None = None,
        asset_id: str | None = None,
        severity: str | None = None,
        state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FindingRecord]:
        """List findings matching optional filter criteria with eager-loaded asset and service."""
        with self.db.session() as session:
            stmt = (
                select(FindingRecord)
                .options(selectinload(FindingRecord.asset), selectinload(FindingRecord.service))
                .order_by(FindingRecord.created_at.desc())
            )
            if assessment_id:
                stmt = stmt.where(
                    (FindingRecord.assessment_id == assessment_id)
                    | (FindingRecord.assessment_id.startswith(assessment_id))
                )
            if asset_id:
                stmt = stmt.where(
                    (FindingRecord.asset_id == asset_id)
                    | (FindingRecord.asset_id.startswith(asset_id))
                )
            if severity:
                stmt = stmt.where(FindingRecord.severity == severity.lower())
            if state:
                stmt = stmt.where(FindingRecord.state == state.lower())

            stmt = stmt.limit(limit).offset(offset)
            return list(session.execute(stmt).scalars().all())

    def get_finding(self, finding_id: str) -> FindingRecord | None:
        """Retrieve finding by UUID or UUID prefix with eager-loaded relationships."""
        with self.db.session() as session:
            stmt = (
                select(FindingRecord)
                .options(
                    selectinload(FindingRecord.assessment),
                    selectinload(FindingRecord.asset),
                    selectinload(FindingRecord.service),
                )
                .where((FindingRecord.id == finding_id) | (FindingRecord.id.startswith(finding_id)))
            )
            return session.execute(stmt).scalars().first()

    def update_finding_state(self, finding_id: str, new_state: str) -> FindingRecord | None:
        """Update finding state (e.g. false_positive, accepted_risk) and bump updated_at timestamp."""
        with self.db.session() as session:
            stmt = select(FindingRecord).where(
                (FindingRecord.id == finding_id) | (FindingRecord.id.startswith(finding_id))
            )
            finding = session.execute(stmt).scalars().first()
            if finding:
                finding.state = new_state.lower()
                finding.updated_at = datetime.now(UTC)
                session.flush()
                session.refresh(finding)
            return finding
