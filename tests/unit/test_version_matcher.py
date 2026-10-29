"""Unit tests for semantic version parsing, range comparison, and distro backport detection."""

from reconforge.intelligence.models import CVEItem, CVEMatchLevel
from reconforge.intelligence.version_matcher import (
    compare_versions,
    detect_distro_backport,
    evaluate_cve_match,
    is_version_in_range,
    parse_loose_version,
)


def test_parse_loose_version():
    nums, _ = parse_loose_version("8.9p1")
    assert nums == [8, 9, 1]

    nums, _ = parse_loose_version("2.4.49")
    assert nums == [2, 4, 49]

    nums, _ = parse_loose_version("v1.20.0-rc1")
    assert nums == [1, 20, 0]


def test_compare_versions_pep440_and_loose():
    # Strict semver
    assert compare_versions("2.4.49", "2.4.50") == -1
    assert compare_versions("2.4.50", "2.4.49") == 1
    assert compare_versions("2.4.49", "2.4.49") == 0

    # OpenSSH patchlevel notation
    assert compare_versions("8.9p1", "9.8p1") == -1
    assert compare_versions("8.9p1", "8.5p1") == 1
    assert compare_versions("8.9p1", "8.9p1") == 0


def test_detect_distro_backport():
    # Ubuntu package banner
    assert (
        detect_distro_backport("8.9p1-3ubuntu0.10", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
        is True
    )

    # Debian package banner
    assert detect_distro_backport("2.4.38-3+deb10u4", "Apache/2.4.38 (Debian)") is True

    # RHEL / Enterprise Linux banner
    assert detect_distro_backport("8.0.28-1.el8_5", "MySQL 8.0.28 el8") is True

    # Upstream unpatched source compile
    assert detect_distro_backport("8.9p1", "SSH-2.0-OpenSSH_8.9p1") is False
    assert detect_distro_backport("2.4.49", "Apache/2.4.49 (Unix)") is False


def test_is_version_in_range_boundaries():
    # Range: [8.5p1, 9.8p1)
    crit = {"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"}
    assert is_version_in_range("8.5p1", crit) is True
    assert is_version_in_range("8.9p1", crit) is True
    assert is_version_in_range("9.7p1", crit) is True
    assert is_version_in_range("9.8p1", crit) is False
    assert is_version_in_range("8.4p1", crit) is False

    # Exact version
    exact_crit = {"exactVersion": "2.4.49"}
    assert is_version_in_range("2.4.49", exact_crit) is True
    assert is_version_in_range("2.4.50", exact_crit) is False


def test_evaluate_cve_match_confidence_tiers():
    cve = CVEItem(
        cve_id="CVE-2024-6387",
        description="regreSSHion vulnerability in OpenSSH",
        affected_cpes=["cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*"],
        version_criteria=[{"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"}],
    )

    # 1. Clean upstream match -> STRONG_CANDIDATE
    matched, level, rationale = evaluate_cve_match("8.9p1", "SSH-2.0-OpenSSH_8.9p1", cve)
    assert matched is True
    assert level == CVEMatchLevel.STRONG_CANDIDATE
    assert "squarely within" in rationale

    # 2. Distro package match -> MANUAL_VERIFICATION_REQUIRED
    matched, level, rationale = evaluate_cve_match(
        "8.9p1", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", cve
    )
    assert matched is True
    assert level == CVEMatchLevel.MANUAL_VERIFICATION_REQUIRED
    assert "backported" in rationale

    # 3. Version outside range -> no match
    matched, level, _ = evaluate_cve_match("9.8p1", "SSH-2.0-OpenSSH_9.8p1", cve)
    assert matched is False

    # 4. Missing version string -> INSUFFICIENT_EVIDENCE
    matched, level, _ = evaluate_cve_match(None, "SSH-2.0-OpenSSH", cve)
    assert matched is False
    assert level == CVEMatchLevel.INSUFFICIENT_EVIDENCE
