"""Assessment snapshot export, import, and untrusted input validation engine."""

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from reconforge.core.exceptions import ConfigurationError
from reconforge.fingerprinting.probes.base import sanitize_banner
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import AssessmentRecord, AssetRecord, ServiceRecord
from reconforge.utils.network import parse_ip_or_network

logger = logging.getLogger("reconforge.inventory.snapshot")

CURRENT_SNAPSHOT_SCHEMA_VERSION = "1.0.0"


class SnapshotService(BaseModel):
    """Validated service record in snapshot."""

    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp", max_length=10)
    service_name: str = Field(default="unknown", max_length=50)
    product: str | None = Field(default=None, max_length=100)
    version: str | None = Field(default=None, max_length=100)
    confidence: str = Field(default="unknown", max_length=20)
    banner_snippet: str | None = Field(default=None, max_length=1024)
    cpe_candidate: str | None = Field(default=None, max_length=255)
    tls_metadata: dict[str, Any] | None = Field(default=None)
    first_observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(default="snapshot_import", max_length=50)

    @field_validator("banner_snippet")
    @classmethod
    def sanitize_banner_text(cls, v: str | None) -> str | None:
        if v:
            return sanitize_banner(v, max_length=1024)
        return v


class SnapshotAsset(BaseModel):
    """Validated asset record in snapshot."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    ip_address: str = Field(..., max_length=45)
    address_family: str = Field(default="ipv4", max_length=10)
    observed_hostnames: list[str] = Field(default_factory=list)
    asset_type: str = Field(default="host", max_length=50)
    criticality: str = Field(default="medium", max_length=20)
    first_observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    discovery_sources: list[str] = Field(default_factory=list)
    services: list[SnapshotService] = Field(default_factory=list)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Strict validation: must be a parseable IP address
        parsed = parse_ip_or_network(v)
        return str(parsed)


class SnapshotAssessment(BaseModel):
    """Assessment execution metadata in snapshot."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(default="Assessment", max_length=150)
    scope_config: dict[str, Any] = Field(default_factory=dict)
    scanner_version: str = Field(default="0.3.0", max_length=30)
    status: str = Field(default="completed", max_length=20)
    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = Field(default=None)
    coverage_metrics: dict[str, Any] = Field(default_factory=dict)
    error_summary: str | None = Field(default=None, max_length=2048)


class AssessmentSnapshot(BaseModel):
    """Top-level versioned assessment snapshot document."""

    schema_version: str = Field(default=CURRENT_SNAPSHOT_SCHEMA_VERSION)
    exported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assessment: SnapshotAssessment
    assets: list[SnapshotAsset] = Field(default_factory=list)


class SnapshotManager:
    """Handles secure export and import of assessment snapshots with untrusted input defenses."""

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        self.db.init_db()

    def export_snapshot(self, assessment_id: str) -> str:
        """Export an assessment and its inventoried assets to a versioned JSON snapshot string."""
        with self.db.session() as session:
            stmt = select(AssessmentRecord).where(
                (AssessmentRecord.id == assessment_id)
                | (AssessmentRecord.id.startswith(assessment_id))
            )
            assessment = session.execute(stmt).scalars().first()
            if not assessment:
                raise ConfigurationError(f"Assessment '{assessment_id}' not found.")

            # Load assets associated with the assessment scope or inventory
            asset_stmt = select(AssetRecord)
            assets_db = session.execute(asset_stmt).scalars().all()

            snapshot_assets: list[SnapshotAsset] = []
            for asset in assets_db:
                services = [
                    SnapshotService(
                        port=s.port,
                        protocol=s.protocol,
                        service_name=s.service_name,
                        product=s.product,
                        version=s.version,
                        confidence=s.confidence,
                        banner_snippet=s.banner_snippet,
                        cpe_candidate=s.cpe_candidate,
                        tls_metadata=s.tls_metadata,
                        first_observed_at=s.first_observed_at,
                        last_observed_at=s.last_observed_at,
                        source=s.source,
                    )
                    for s in asset.services
                ]
                snapshot_assets.append(
                    SnapshotAsset(
                        id=asset.id,
                        ip_address=asset.ip_address,
                        address_family=asset.address_family,
                        observed_hostnames=asset.observed_hostnames or [],
                        asset_type=asset.asset_type,
                        criticality=asset.criticality,
                        first_observed_at=asset.first_observed_at,
                        last_observed_at=asset.last_observed_at,
                        discovery_sources=asset.discovery_sources or [],
                        services=services,
                    )
                )

            snapshot = AssessmentSnapshot(
                schema_version=CURRENT_SNAPSHOT_SCHEMA_VERSION,
                exported_at=datetime.now(UTC),
                assessment=SnapshotAssessment(
                    id=assessment.id,
                    name=assessment.name,
                    scope_config=assessment.scope_config,
                    scanner_version=assessment.scanner_version,
                    status=assessment.status,
                    start_time=assessment.start_time,
                    end_time=assessment.end_time,
                    coverage_metrics=assessment.coverage_metrics,
                    error_summary=assessment.error_summary,
                ),
                assets=snapshot_assets,
            )

            return snapshot.model_dump_json(indent=2)

    def import_snapshot(self, raw_json: str | dict) -> AssessmentRecord:
        """Validate and import an untrusted assessment snapshot JSON into the database.

        Raises:
            ConfigurationError: If snapshot is malformed, has incompatible schema version,
                                or fails Pydantic input validation.
        """
        try:
            if isinstance(raw_json, str):
                data = json.loads(raw_json)
            else:
                data = raw_json
        except Exception as err:
            raise ConfigurationError(f"Malformed snapshot JSON: {err}") from err

        # Validate schema version
        schema_ver = data.get("schema_version")
        if schema_ver != CURRENT_SNAPSHOT_SCHEMA_VERSION:
            raise ConfigurationError(
                f"Unsupported snapshot schema version '{schema_ver}'. Expected '{CURRENT_SNAPSHOT_SCHEMA_VERSION}'."
            )

        # Validate against strict Pydantic model (rejects malicious fields or invalid structures)
        try:
            snapshot = AssessmentSnapshot(**data)
        except Exception as err:
            raise ConfigurationError(f"Snapshot validation failed: {err}") from err

        # Atomic persistence with collision resolution
        with self.db.session() as session:
            # Check for existing assessment
            existing_ass = session.execute(
                select(AssessmentRecord).where(AssessmentRecord.id == snapshot.assessment.id)
            ).scalar_one_or_none()

            ass_data = snapshot.assessment
            if existing_ass:
                existing_ass.name = ass_data.name
                existing_ass.status = ass_data.status
                existing_ass.coverage_metrics = ass_data.coverage_metrics
                assessment_obj = existing_ass
            else:
                assessment_obj = AssessmentRecord(
                    id=ass_data.id,
                    name=ass_data.name,
                    scope_config=ass_data.scope_config,
                    scanner_version=ass_data.scanner_version,
                    status=ass_data.status,
                    start_time=ass_data.start_time,
                    end_time=ass_data.end_time,
                    coverage_metrics=ass_data.coverage_metrics,
                    error_summary=ass_data.error_summary,
                )
                session.add(assessment_obj)

            # Process assets and services
            for asset_data in snapshot.assets:
                asset = session.execute(
                    select(AssetRecord).where(AssetRecord.ip_address == asset_data.ip_address)
                ).scalar_one_or_none()

                if asset:
                    if asset_data.last_observed_at > asset.last_observed_at:
                        asset.last_observed_at = asset_data.last_observed_at
                    # Merge hostnames
                    hostnames = set(asset.observed_hostnames or [])
                    hostnames.update(asset_data.observed_hostnames)
                    asset.observed_hostnames = sorted(hostnames)
                else:
                    asset = AssetRecord(
                        id=asset_data.id,
                        ip_address=asset_data.ip_address,
                        address_family=asset_data.address_family,
                        observed_hostnames=asset_data.observed_hostnames,
                        asset_type=asset_data.asset_type,
                        criticality=asset_data.criticality,
                        first_observed_at=asset_data.first_observed_at,
                        last_observed_at=asset_data.last_observed_at,
                        discovery_sources=asset_data.discovery_sources,
                    )
                    session.add(asset)
                    session.flush()

                # Process services for this asset
                for srv_data in asset_data.services:
                    service = session.execute(
                        select(ServiceRecord).where(
                            ServiceRecord.asset_id == asset.id,
                            ServiceRecord.port == srv_data.port,
                            ServiceRecord.protocol == srv_data.protocol,
                        )
                    ).scalar_one_or_none()

                    if service:
                        if srv_data.last_observed_at > service.last_observed_at:
                            service.last_observed_at = srv_data.last_observed_at
                            if srv_data.product:
                                service.product = srv_data.product
                            if srv_data.version:
                                service.version = srv_data.version
                            if srv_data.service_name != "unknown":
                                service.service_name = srv_data.service_name
                            if srv_data.confidence != "unknown":
                                service.confidence = srv_data.confidence
                    else:
                        service = ServiceRecord(
                            id=str(uuid4()),
                            asset_id=asset.id,
                            port=srv_data.port,
                            protocol=srv_data.protocol,
                            service_name=srv_data.service_name,
                            product=srv_data.product,
                            version=srv_data.version,
                            confidence=srv_data.confidence,
                            banner_snippet=srv_data.banner_snippet,
                            cpe_candidate=srv_data.cpe_candidate,
                            tls_metadata=srv_data.tls_metadata,
                            first_observed_at=srv_data.first_observed_at,
                            last_observed_at=srv_data.last_observed_at,
                            source=srv_data.source,
                        )
                        session.add(service)

            session.flush()
            session.refresh(assessment_obj)
            return assessment_obj
