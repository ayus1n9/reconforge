"""SQLAlchemy database models for assets, services, assessments, and findings."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from reconforge.storage.database import Base


class AssetRecord(Base):
    """Normalized network asset record indexed by canonical IP address."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, index=True, nullable=False)
    address_family: Mapped[str] = mapped_column(String(10), nullable=False, default="ipv4")
    observed_hostnames: Mapped[list[str]] = mapped_column(JSON, default=list)
    asset_type: Mapped[str] = mapped_column(String(50), default="host")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
    discovery_sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    extra_metadata: Mapped[dict] = mapped_column(JSON, default=dict)

    # Relationships
    services: Mapped[list["ServiceRecord"]] = relationship(
        "ServiceRecord", back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord", back_populates="asset", cascade="all, delete-orphan"
    )


class ServiceRecord(Base):
    """Network transport service associated with an asset."""

    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp", nullable=False)
    service_name: Mapped[str] = mapped_column(String(50), default="unknown", nullable=False)
    product: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    banner_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_candidate: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tls_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    last_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(String(50), default="reconforge_internal", nullable=False)

    # Relationships
    asset: Mapped["AssetRecord"] = relationship("AssetRecord", back_populates="services")
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord", back_populates="service", cascade="all, delete-orphan"
    )


class AssessmentRecord(Base):
    """Assessment execution metadata, scope, and coverage snapshot."""

    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(150), default="Assessment", nullable=False)
    scope_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    coverage_metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord", back_populates="assessment", cascade="all, delete-orphan"
    )


class FindingRecord(Base):
    """Identified exposure, configuration issue, or vulnerability."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    service_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("services.id", ondelete="SET NULL"), nullable=True, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    priority: Mapped[str] = mapped_column(String(10), default="P4", nullable=False)
    state: Mapped[str] = mapped_column(String(30), default="potential_exposure", nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation_guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    assessment: Mapped["AssessmentRecord"] = relationship(
        "AssessmentRecord", back_populates="findings"
    )
    asset: Mapped["AssetRecord"] = relationship("AssetRecord", back_populates="findings")
    service: Mapped["ServiceRecord | None"] = relationship(
        "ServiceRecord", back_populates="findings"
    )
