"""Asynchronous NIST National Vulnerability Database (NVD) REST API v2.0 client with rate-limiting and offline fallback."""

import asyncio
import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

from reconforge.core.enums import SeverityLevel
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.models import CVEItem

logger = logging.getLogger("reconforge.intelligence.nvd")


class NVDRateLimiter:
    """Token-bucket rate limiter enforcing NIST NVD API usage constraints.

    Default public rate: 5 requests per 30 seconds (~6.0s interval).
    With API key: 50 requests per 30 seconds (~0.6s interval).
    """

    def __init__(self, has_api_key: bool = False):
        self.capacity = 50.0 if has_api_key else 5.0
        self.window = 30.0
        self.fill_rate = self.capacity / self.window
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request token is available."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

                wait_time = (1.0 - self.tokens) / self.fill_rate
                await asyncio.sleep(min(wait_time, 2.0))


class AsyncNVDClient:
    """Asynchronous client for NIST NVD API 2.0 with backoff, bounded reads, and offline cache fallback."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DEFAULT_USER_AGENT = "ReconForge/0.5.0 (+https://github.com/ayus1n9/reconforge)"
    MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB payload limit

    def __init__(
        self,
        api_key: str | None = None,
        cache: VulnerabilityCache | None = None,
        timeout: float = 15.0,
        offline_mode: bool = False,
    ):
        self.api_key = api_key
        self.cache = cache or VulnerabilityCache()
        self.timeout = timeout
        self.offline_mode = offline_mode
        self.limiter = NVDRateLimiter(has_api_key=bool(api_key))

    def _sync_fetch(self, url: str) -> str:
        """Synchronously execute bounded HTTP GET request with timeouts and security limits."""
        req = urllib.request.Request(url)
        req.add_header("User-Agent", self.DEFAULT_USER_AGENT)
        req.add_header("Accept", "application/json")
        if self.api_key:
            req.add_header("apiKey", self.api_key)

        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
            total_bytes = 0
            chunks = []
            while True:
                chunk = resp.read(64 * 1024)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > self.MAX_RESPONSE_BYTES:
                    raise ValueError(
                        f"NVD payload exceeded {self.MAX_RESPONSE_BYTES} bytes limit (received {total_bytes} bytes)"
                    )
                chunks.append(chunk)

            return b"".join(chunks).decode("utf-8")

    async def _fetch_with_backoff(self, params: dict[str, str]) -> dict[str, Any] | None:
        """Execute request with rate limiting and exponential backoff on 429/503."""
        query_string = urllib.parse.urlencode(params)
        url = f"{self.NVD_API_URL}?{query_string}"

        max_retries = 3
        backoff = 2.0

        for attempt in range(max_retries):
            await self.limiter.acquire()
            try:
                raw_data = await asyncio.to_thread(self._sync_fetch, url)
                return json.loads(raw_data)
            except urllib.error.HTTPError as http_err:
                if http_err.code in {429, 503} and attempt < max_retries - 1:
                    jitter = random.uniform(0.5, 1.5)  # nosec B311
                    sleep_time = (backoff * (2**attempt)) + jitter
                    logger.warning(
                        "NVD API returned HTTP %d on attempt %d/%d. Backing off for %.2fs",
                        http_err.code,
                        attempt + 1,
                        max_retries,
                        sleep_time,
                    )
                    await asyncio.sleep(sleep_time)
                else:
                    logger.error("NVD HTTP Error %d: %s", http_err.code, http_err.reason)
                    return None
            except Exception as e:
                logger.warning("NVD API request failed: %s", e)
                return None

        return None

    def _parse_cve_item(self, vuln_dict: dict[str, Any]) -> CVEItem | None:
        """Parse NVD JSON 2.0 vulnerability item into normalized domain model."""
        cve_data = vuln_dict.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            return None

        # Extract English description
        descriptions = cve_data.get("descriptions", [])
        desc = "No description provided."
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", desc)
                break

        # Extract CVSS v3.1 or v3.0 metrics
        metrics = cve_data.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        severity = SeverityLevel.MEDIUM

        v3_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        if v3_list:
            v3_primary = v3_list[0].get("cvssData", {})
            cvss_score = v3_primary.get("baseScore")
            cvss_vector = v3_primary.get("vectorString")
            base_sev = v3_primary.get("baseSeverity", "MEDIUM").upper()
            if base_sev == "CRITICAL":
                severity = SeverityLevel.CRITICAL
            elif base_sev == "HIGH":
                severity = SeverityLevel.HIGH
            elif base_sev == "MEDIUM":
                severity = SeverityLevel.MEDIUM
            elif base_sev == "LOW":
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.INFO

        # Extract CWEs
        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for d in weakness.get("description", []):
                val = d.get("value")
                if val and val.startswith("CWE-"):
                    cwe_ids.append(val)

        # Extract affected CPEs and criteria
        affected_cpes = []
        version_criteria = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_crit = match.get("criteria")
                    if cpe_crit:
                        affected_cpes.append(cpe_crit)
                    crit_dict = {}
                    for key in [
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    ]:
                        if match.get(key):
                            crit_dict[key] = match[key]
                    if crit_dict:
                        version_criteria.append(crit_dict)

        # Extract references
        references = [r.get("url") for r in cve_data.get("references", []) if r.get("url")]

        return CVEItem(
            cve_id=cve_id,
            description=desc,
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            severity=severity,
            cwe_ids=cwe_ids,
            affected_cpes=affected_cpes,
            version_criteria=version_criteria,
            references=references[:10],
            published_date=datetime.now(UTC),
            last_modified_date=datetime.now(UTC),
            is_known_exploited=False,
        )

    async def get_cve(self, cve_id: str) -> CVEItem | None:
        """Fetch CVE by identifier, querying local cache first or online if enabled."""
        norm_id = cve_id.strip().upper()
        # Fast cache lookup
        cached = self.cache.get_cve(norm_id)
        if cached:
            return cached

        if self.offline_mode:
            return None

        data = await self._fetch_with_backoff({"cveId": norm_id})
        if not data:
            return None

        vulns = data.get("vulnerabilities", [])
        if vulns:
            item = self._parse_cve_item(vulns[0])
            if item:
                self.cache.store_cve(item)
                return item

        return None

    async def search_by_cpe(self, cpe_match_string: str) -> list[CVEItem]:
        """Search CVEs affecting a given CPE 2.3 criteria."""
        if self.offline_mode:
            # Query local cache
            parts = cpe_match_string.split(":")
            prod = parts[4] if len(parts) > 4 else None
            return self.cache.search_cves(cpe_product=prod)

        data = await self._fetch_with_backoff({"cpeName": cpe_match_string, "resultsPerPage": "20"})
        if not data:
            # Fallback to cache on error
            parts = cpe_match_string.split(":")
            prod = parts[4] if len(parts) > 4 else None
            return self.cache.search_cves(cpe_product=prod)

        items: list[CVEItem] = []
        for vuln in data.get("vulnerabilities", []):
            parsed = self._parse_cve_item(vuln)
            if parsed:
                items.append(parsed)
                self.cache.store_cve(parsed)

        return items

    async def search_by_keyword(self, keyword: str) -> list[CVEItem]:
        """Search CVEs by text keyword with cache fallback."""
        if self.offline_mode:
            return self.cache.search_cves(query=keyword)

        data = await self._fetch_with_backoff({"keywordSearch": keyword, "resultsPerPage": "20"})
        if not data:
            return self.cache.search_cves(query=keyword)

        items: list[CVEItem] = []
        for vuln in data.get("vulnerabilities", []):
            parsed = self._parse_cve_item(vuln)
            if parsed:
                items.append(parsed)
                self.cache.store_cve(parsed)

        return items
