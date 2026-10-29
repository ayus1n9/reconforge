"""Local vulnerability intelligence cache management and SQLite persistence."""

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from reconforge.core.enums import SeverityLevel
from reconforge.intelligence.builtin_cves import BUILTIN_CVES
from reconforge.intelligence.models import CVEItem
from reconforge.storage.database import DatabaseManager
from reconforge.storage.models import CVECacheRecord

logger = logging.getLogger("reconforge.intelligence.cache")


class VulnerabilityCache:
    """Manages offline-first vulnerability storage and fast candidate lookup."""

    def __init__(self, db_manager: DatabaseManager | None = None):
        self.db = db_manager or DatabaseManager()
        self.init_cache()

    def init_cache(self) -> None:
        """Initialize database schema and seed curated built-in CVEs if cache is empty."""
        self.db.init_db()
        self.seed_builtins(overwrite=False)

    def _record_to_cve(self, record: CVECacheRecord) -> CVEItem:
        """Convert a database CVECacheRecord into a domain CVEItem model."""
        return CVEItem(
            cve_id=record.cve_id,
            description=record.description,
            cvss_v3_score=record.cvss_v3_score,
            cvss_v3_vector=record.cvss_v3_vector,
            severity=SeverityLevel(record.severity),
            cwe_ids=list(record.cwe_ids or []),
            affected_cpes=list(record.affected_cpes or []),
            version_criteria=list(record.version_criteria or []),
            references=list(record.references or []),
            published_date=record.published_date,
            last_modified_date=record.last_modified_date,
            is_known_exploited=record.is_known_exploited,
        )

    def seed_builtins(self, overwrite: bool = False) -> int:
        """Seed local cache with curated high-impact vulnerability intelligence."""
        count = 0
        with self.db.session() as session:
            for cve in BUILTIN_CVES:
                existing = session.get(CVECacheRecord, cve.cve_id)
                if not existing:
                    record = CVECacheRecord(
                        cve_id=cve.cve_id,
                        description=cve.description,
                        cvss_v3_score=cve.cvss_v3_score,
                        cvss_v3_vector=cve.cvss_v3_vector,
                        severity=cve.severity.value,
                        cwe_ids=cve.cwe_ids,
                        affected_cpes=cve.affected_cpes,
                        version_criteria=cve.version_criteria,
                        references=cve.references,
                        published_date=cve.published_date,
                        last_modified_date=cve.last_modified_date,
                        is_known_exploited=cve.is_known_exploited,
                        cached_at=datetime.now(UTC),
                    )
                    session.add(record)
                    count += 1
                elif overwrite:
                    existing.description = cve.description
                    existing.cvss_v3_score = cve.cvss_v3_score
                    existing.cvss_v3_vector = cve.cvss_v3_vector
                    existing.severity = cve.severity.value
                    existing.cwe_ids = cve.cwe_ids
                    existing.affected_cpes = cve.affected_cpes
                    existing.version_criteria = cve.version_criteria
                    existing.references = cve.references
                    existing.published_date = cve.published_date
                    existing.last_modified_date = cve.last_modified_date
                    existing.is_known_exploited = cve.is_known_exploited
                    existing.cached_at = datetime.now(UTC)
                    count += 1
            session.commit()
        if count > 0:
            logger.info("Seeded %d CVE records into vulnerability cache", count)
        return count

    def get_cve(self, cve_id: str) -> CVEItem | None:
        """Retrieve a cached CVE item by exact identifier."""
        norm_id = cve_id.strip().upper()
        with self.db.session() as session:
            record = session.get(CVECacheRecord, norm_id)
            if record:
                return self._record_to_cve(record)
        return None

    def store_cve(self, cve: CVEItem) -> None:
        """Insert or update a CVE item in the local cache."""
        with self.db.session() as session:
            record = session.get(CVECacheRecord, cve.cve_id)
            now = datetime.now(UTC)
            if record:
                record.description = cve.description
                record.cvss_v3_score = cve.cvss_v3_score
                record.cvss_v3_vector = cve.cvss_v3_vector
                record.severity = cve.severity.value
                record.cwe_ids = cve.cwe_ids
                record.affected_cpes = cve.affected_cpes
                record.version_criteria = cve.version_criteria
                record.references = cve.references
                record.published_date = cve.published_date
                record.last_modified_date = cve.last_modified_date
                record.is_known_exploited = cve.is_known_exploited
                record.cached_at = now
            else:
                record = CVECacheRecord(
                    cve_id=cve.cve_id,
                    description=cve.description,
                    cvss_v3_score=cve.cvss_v3_score,
                    cvss_v3_vector=cve.cvss_v3_vector,
                    severity=cve.severity.value,
                    cwe_ids=cve.cwe_ids,
                    affected_cpes=cve.affected_cpes,
                    version_criteria=cve.version_criteria,
                    references=cve.references,
                    published_date=cve.published_date,
                    last_modified_date=cve.last_modified_date,
                    is_known_exploited=cve.is_known_exploited,
                    cached_at=now,
                )
                session.add(record)
            session.commit()

    def store_cves(self, cves: list[CVEItem]) -> int:
        """Bulk insert or update CVE intelligence records."""
        for cve in cves:
            self.store_cve(cve)
        return len(cves)

    def search_cves(
        self,
        query: str | None = None,
        cpe_product: str | None = None,
        min_cvss: float | None = None,
        severity: SeverityLevel | None = None,
        is_known_exploited: bool | None = None,
    ) -> list[CVEItem]:
        """Search cached CVEs by free-text keywords, CPE product, minimum score, or severity."""
        results: list[CVEItem] = []
        with self.db.session() as session:
            stmt = select(CVECacheRecord)
            if severity:
                stmt = stmt.where(CVECacheRecord.severity == severity.value)
            if min_cvss is not None:
                stmt = stmt.where(CVECacheRecord.cvss_v3_score >= min_cvss)
            if is_known_exploited is not None:
                stmt = stmt.where(CVECacheRecord.is_known_exploited == is_known_exploited)

            records = session.execute(stmt).scalars().all()
            for record in records:
                item = self._record_to_cve(record)
                # Filter by CPE product match if requested
                if cpe_product:
                    prod = cpe_product.lower()
                    matched_cpe = any(prod in cpe.lower() for cpe in item.affected_cpes)
                    if not matched_cpe:
                        continue

                # Filter by keyword query if requested
                if query:
                    q = query.lower()
                    in_id = q in item.cve_id.lower()
                    in_desc = q in item.description.lower()
                    in_cpes = any(q in cpe.lower() for cpe in item.affected_cpes)
                    if not (in_id or in_desc or in_cpes):
                        continue

                results.append(item)

        return results

    def get_all_cves(self) -> list[CVEItem]:
        """Return all vulnerability intelligence items in local cache."""
        with self.db.session() as session:
            records = session.execute(select(CVECacheRecord)).scalars().all()
            return [self._record_to_cve(r) for r in records]

    def get_stats(self) -> dict[str, Any]:
        """Return summary metrics of the vulnerability cache."""
        with self.db.session() as session:
            total = session.execute(select(func.count(CVECacheRecord.cve_id))).scalar_one()
            known_exploited = session.execute(
                select(func.count(CVECacheRecord.cve_id)).where(
                    CVECacheRecord.is_known_exploited.is_(True)
                )
            ).scalar_one()
            last_cached = session.execute(
                select(func.max(CVECacheRecord.cached_at))
            ).scalar_one_or_none()

            severity_counts: dict[str, int] = {}
            for sev in SeverityLevel:
                count = session.execute(
                    select(func.count(CVECacheRecord.cve_id)).where(
                        CVECacheRecord.severity == sev.value
                    )
                ).scalar_one()
                severity_counts[sev.value] = count

            return {
                "total_cves": total,
                "known_exploited": known_exploited,
                "last_cached_at": last_cached.isoformat() if last_cached else None,
                "by_severity": severity_counts,
            }
