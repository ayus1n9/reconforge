"""Vulnerability intelligence and CVE correlation package."""

from reconforge.intelligence.builtin_cves import BUILTIN_CVES
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.correlator import VulnerabilityCorrelator
from reconforge.intelligence.cpe import CPE
from reconforge.intelligence.models import (
    CVECorrelationResult,
    CVEItem,
    CVEMatchLevel,
)
from reconforge.intelligence.nvd_client import AsyncNVDClient, NVDRateLimiter
from reconforge.intelligence.version_matcher import (
    compare_versions,
    detect_distro_backport,
    evaluate_cve_match,
    is_version_in_range,
)

__all__ = [
    "CPE",
    "CVEItem",
    "CVEMatchLevel",
    "CVECorrelationResult",
    "BUILTIN_CVES",
    "VulnerabilityCache",
    "AsyncNVDClient",
    "NVDRateLimiter",
    "VulnerabilityCorrelator",
    "compare_versions",
    "detect_distro_backport",
    "evaluate_cve_match",
    "is_version_in_range",
]
