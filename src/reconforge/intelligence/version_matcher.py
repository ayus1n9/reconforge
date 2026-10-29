"""Semantic version comparison and distro-backport detection engine for CVE correlation."""

import re
from typing import Any

from packaging.version import InvalidVersion, Version

from reconforge.intelligence.models import CVEItem, CVEMatchLevel

# Patterns identifying Linux distribution package maintenance strings
DISTRO_BACKPORT_PATTERNS = [
    re.compile(r"ubuntu[\d.]*", re.IGNORECASE),
    re.compile(r"deb[\d.]+", re.IGNORECASE),
    re.compile(r"debian", re.IGNORECASE),
    re.compile(r"el\d+", re.IGNORECASE),  # Enterprise Linux (RHEL/CentOS/Alma/Rocky)
    re.compile(r"rhel[\d.]*", re.IGNORECASE),
    re.compile(r"centos", re.IGNORECASE),
    re.compile(r"amzn\d*", re.IGNORECASE),
    re.compile(r"suse", re.IGNORECASE),
    re.compile(r"arch", re.IGNORECASE),
    re.compile(r"alpine", re.IGNORECASE),
]


def detect_distro_backport(version_str: str | None, banner: str | None = None) -> bool:
    """Detect whether a version string or service banner indicates a Linux distribution package.

    Distribution maintainers commonly backport security patches into older upstream
    software versions without incrementing the upstream version number (e.g.
    'OpenSSH_8.9p1 Ubuntu-3ubuntu0.10' has patches for regreSSHion backported).
    """
    text_to_check = f"{version_str or ''} {banner or ''}"
    return any(p.search(text_to_check) for p in DISTRO_BACKPORT_PATTERNS)


def parse_loose_version(version_str: str) -> tuple[list[int], str]:
    """Parse irregular or non-PEP440 version strings into comparable numeric sequences.

    Handles software formats such as:
    - '8.9p1' -> ([8, 9, 1], "")
    - '2.4.49' -> ([2, 4, 49], "")
    - '1.18.0-1ubuntu1' -> ([1, 18, 0], "1ubuntu1")
    - 'v1.2.3' -> ([1, 2, 3], "")
    """
    clean = version_str.strip().lstrip("vV")
    # Split off distro tags or release suffixes separated by '-' or '+'
    base_part = re.split(r"[-+~]", clean)[0]

    # Convert common patchlevel notation like 8.9p1 or 1.2a into 8.9.1 or 1.2.1
    normalized = re.sub(r"([0-9]+)[pP]([0-9]+)", r"\1.\2", base_part)
    normalized = re.sub(
        r"([0-9]+)([a-zA-Z]+)([0-9]*)",
        r"\1.\3" if re.search(r"[0-9]+[a-zA-Z]+[0-9]+", base_part) else r"\1",
        normalized,
    )

    # Extract all digit sequences
    numbers = [int(n) for n in re.findall(r"\d+", normalized)]
    suffix = clean[len(base_part) :]
    return numbers, suffix


def compare_versions(v1_str: str, v2_str: str) -> int:
    """Compare two version strings.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    # First attempt PEP 440 strict comparison
    try:
        # Strip common 'p' notations before packaging Version if needed
        norm_v1 = re.sub(r"([0-9]+)[pP]([0-9]+)", r"\1.post\2", v1_str.strip().lstrip("vV"))
        norm_v2 = re.sub(r"([0-9]+)[pP]([0-9]+)", r"\1.post\2", v2_str.strip().lstrip("vV"))
        pv1 = Version(norm_v1)
        pv2 = Version(norm_v2)
        if pv1 < pv2:
            return -1
        elif pv1 > pv2:
            return 1
        return 0
    except InvalidVersion:
        pass

    # Fallback to loose numeric tuple comparison
    nums1, _ = parse_loose_version(v1_str)
    nums2, _ = parse_loose_version(v2_str)

    max_len = max(len(nums1), len(nums2))
    pad1 = nums1 + [0] * (max_len - len(nums1))
    pad2 = nums2 + [0] * (max_len - len(nums2))

    if pad1 < pad2:
        return -1
    elif pad1 > pad2:
        return 1
    return 0


def is_version_in_range(version: str, criteria: dict[str, Any]) -> bool:
    """Check whether a software release version satisfies an NVD version boundary criteria."""
    start_inc = criteria.get("versionStartIncluding")
    start_exc = criteria.get("versionStartExcluding")
    end_inc = criteria.get("versionEndIncluding")
    end_exc = criteria.get("versionEndExcluding")

    # If no boundaries are defined, check for exact match if provided
    exact_ver = criteria.get("exactVersion")
    if exact_ver:
        return compare_versions(version, exact_ver) == 0

    if start_inc is not None and compare_versions(version, str(start_inc)) < 0:
        return False
    if start_exc is not None and compare_versions(version, str(start_exc)) <= 0:
        return False
    if end_inc is not None and compare_versions(version, str(end_inc)) > 0:
        return False
    if end_exc is not None and compare_versions(version, str(end_exc)) >= 0:
        return False

    return True


def evaluate_cve_match(
    version: str | None,
    banner: str | None,
    cve: CVEItem,
) -> tuple[bool, CVEMatchLevel, str]:
    """Correlate a detected service version and banner against a CVE item.

    Returns:
        (matched, match_level, rationale)
    """
    if not version or version.strip() in {"", "*", "-"}:
        return (
            False,
            CVEMatchLevel.INSUFFICIENT_EVIDENCE,
            "Service banner identified product, but specific software version could not be extracted.",
        )

    clean_version = version.strip()
    has_backport = detect_distro_backport(clean_version, banner)

    # If the CVE has explicit version criteria boundaries
    if cve.version_criteria:
        matched_any_criteria = False
        matching_rule_desc = ""

        for rule in cve.version_criteria:
            if is_version_in_range(clean_version, rule):
                matched_any_criteria = True
                matching_rule_desc = str(rule)
                break

        if not matched_any_criteria:
            return (
                False,
                CVEMatchLevel.POSSIBLE_MATCH,
                f"Version '{clean_version}' is outside affected boundaries: {cve.version_criteria}",
            )

        # Version matches boundary criteria
        if has_backport:
            return (
                True,
                CVEMatchLevel.MANUAL_VERIFICATION_REQUIRED,
                f"Version '{clean_version}' matches criteria {matching_rule_desc}, but distribution package identifiers "
                f"were detected in banner ('{banner or clean_version}'). Security patches may have been backported.",
            )

        return (
            True,
            CVEMatchLevel.STRONG_CANDIDATE,
            f"Observed version '{clean_version}' falls squarely within affected version range: {matching_rule_desc}.",
        )

    # If no explicit criteria ranges exist, compare against affected CPE versions
    for cpe_str in cve.affected_cpes:
        parts = cpe_str.split(":")
        if len(parts) > 5:
            cpe_ver = parts[5]
            if cpe_ver not in {"*", "-"}:
                if compare_versions(clean_version, cpe_ver) == 0:
                    if has_backport:
                        return (
                            True,
                            CVEMatchLevel.MANUAL_VERIFICATION_REQUIRED,
                            f"Version '{clean_version}' matches affected CPE version '{cpe_ver}', "
                            "but distro packaging indicators suggest backported security patches.",
                        )
                    return (
                        True,
                        CVEMatchLevel.STRONG_CANDIDATE,
                        f"Observed version '{clean_version}' exactly matches affected CPE version '{cpe_ver}'.",
                    )

    return (
        False,
        CVEMatchLevel.INSUFFICIENT_EVIDENCE,
        f"Version '{clean_version}' could not be matched against affected CPE configurations.",
    )
