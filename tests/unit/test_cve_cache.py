"""Unit tests for SQLite vulnerability intelligence cache management."""

from reconforge.core.enums import SeverityLevel
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.models import CVEItem
from reconforge.storage.database import DatabaseManager


def test_cache_initialization_and_builtins_seeding():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)

    stats = cache.get_stats()
    assert stats["total_cves"] >= 8
    assert stats["by_severity"]["critical"] >= 3

    item = cache.get_cve("CVE-2024-6387")
    assert item is not None
    assert item.cve_id == "CVE-2024-6387"
    assert item.cvss_v3_score == 8.1
    assert item.severity == SeverityLevel.HIGH


def test_cache_search_by_query_and_product():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)

    ssh_items = cache.search_cves(query="OpenSSH")
    assert len(ssh_items) >= 2
    cve_ids = [c.cve_id for c in ssh_items]
    assert "CVE-2024-6387" in cve_ids

    # Search by product
    apache_items = cache.search_cves(cpe_product="http_server")
    assert any("41773" in c.cve_id for c in apache_items)


def test_cache_search_by_severity_and_cvss():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)

    crit_items = cache.search_cves(severity=SeverityLevel.CRITICAL)
    for item in crit_items:
        assert item.severity == SeverityLevel.CRITICAL

    high_cvss = cache.search_cves(min_cvss=9.0)
    for item in high_cvss:
        assert item.cvss_v3_score is not None and item.cvss_v3_score >= 9.0


def test_cache_upsert_custom_cve():
    db = DatabaseManager("sqlite:///:memory:")
    cache = VulnerabilityCache(db)

    custom = CVEItem(
        cve_id="CVE-2099-0001",
        description="Hypothetical critical vulnerability",
        cvss_v3_score=9.9,
        severity=SeverityLevel.CRITICAL,
        affected_cpes=["cpe:2.3:a:example:daemon:*:*:*:*:*:*:*:*"],
    )

    cache.store_cve(custom)
    fetched = cache.get_cve("CVE-2099-0001")
    assert fetched is not None
    assert fetched.description == "Hypothetical critical vulnerability"

    # Update description
    custom.description = "Updated description"
    cache.store_cve(custom)
    updated = cache.get_cve("CVE-2099-0001")
    assert updated is not None
    assert updated.description == "Updated description"
