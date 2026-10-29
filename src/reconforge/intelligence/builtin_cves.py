"""Curated offline vulnerability intelligence dataset for deterministic benchmarking and air-gapped environments."""

from datetime import UTC, datetime

from reconforge.core.enums import SeverityLevel
from reconforge.intelligence.models import CVEItem

BUILTIN_CVES: list[CVEItem] = [
    CVEItem(
        cve_id="CVE-2024-6387",
        description=(
            "A signal handler race condition in OpenSSH's server (sshd) allows unauthenticated remote "
            "code execution as root on glibc-based Linux systems (known as 'regreSSHion')."
        ),
        cvss_v3_score=8.1,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-362"],
        affected_cpes=["cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*"],
        version_criteria=[
            {"versionStartIncluding": "8.5p1", "versionEndExcluding": "9.8p1"},
        ],
        references=[
            "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        ],
        published_date=datetime(2024, 7, 1, 0, 0, tzinfo=UTC),
        last_modified_date=datetime(2024, 7, 2, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
    CVEItem(
        cve_id="CVE-2023-48795",
        description=(
            "Prefix truncation attack in the SSH transport protocol (Terrapin Attack) allows a man-in-the-middle "
            "attacker to bypass integrity checks and truncate extension negotiation messages without detection."
        ),
        cvss_v3_score=5.9,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-354"],
        affected_cpes=[
            "cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:dropbear_ssh_project:dropbear:*:*:*:*:*:*:*:*",
        ],
        version_criteria=[
            {"versionEndExcluding": "9.6p1"},
        ],
        references=[
            "https://terrapin-attack.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
        ],
        published_date=datetime(2023, 12, 18, 0, 0, tzinfo=UTC),
        is_known_exploited=False,
    ),
    CVEItem(
        cve_id="CVE-2018-15473",
        description=(
            "OpenSSH through 7.7 is vulnerable to user enumeration due to sending different responses "
            "for authentication requests with valid vs. invalid usernames."
        ),
        cvss_v3_score=5.3,
        cvss_v3_vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-200"],
        affected_cpes=["cpe:2.3:a:openssh:openssh:*:*:*:*:*:*:*:*"],
        version_criteria=[
            {"versionEndIncluding": "7.7"},
        ],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        ],
        published_date=datetime(2018, 8, 17, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
    CVEItem(
        cve_id="CVE-2021-41773",
        description=(
            "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. "
            "An attacker could use a path traversal attack to map URLs to files outside the expected document root."
        ),
        cvss_v3_score=7.5,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-22"],
        affected_cpes=["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
        version_criteria=[
            {"exactVersion": "2.4.49"},
        ],
        references=[
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        ],
        published_date=datetime(2021, 10, 5, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
    CVEItem(
        cve_id="CVE-2021-42013",
        description=(
            "Incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.49 and 2.4.50 allowed remote attackers "
            "to perform directory traversal and potentially remote code execution if CGI scripts are enabled."
        ),
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-22"],
        affected_cpes=["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
        version_criteria=[
            {"versionStartIncluding": "2.4.49", "versionEndIncluding": "2.4.50"},
        ],
        references=[
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        ],
        published_date=datetime(2021, 10, 7, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
    CVEItem(
        cve_id="CVE-2022-0543",
        description=(
            "Lua sandbox escape in Debian/Ubuntu packaged Redis instances allows remote attackers to execute "
            "arbitrary Lua code and escape to the host system via package.loadlib."
        ),
        cvss_v3_score=10.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-269"],
        affected_cpes=["cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"],
        version_criteria=[
            {"versionStartIncluding": "5.0.0", "versionEndExcluding": "6.2.7"},
        ],
        references=[
            "https://www.ubercomp.com/posts/2022-01-20_redis_rce",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
        ],
        published_date=datetime(2022, 2, 18, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
    CVEItem(
        cve_id="CVE-2011-2523",
        description=(
            "vsftpd 2.3.4 contains a backdoor in the downloaded archive that opens a listening root shell "
            "on TCP port 6200 when a username containing the smiley token ':)' is supplied."
        ),
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-506"],
        affected_cpes=["cpe:2.3:a:vsftpd_project:vsftpd:2.3.4:*:*:*:*:*:*:*"],
        version_criteria=[
            {"exactVersion": "2.3.4"},
        ],
        references=[
            "https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        ],
        published_date=datetime(2011, 7, 3, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
    CVEItem(
        cve_id="CVE-2021-44228",
        description=(
            "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not "
            "protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell)."
        ),
        cvss_v3_score=10.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-502", "CWE-917"],
        affected_cpes=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
        version_criteria=[
            {"versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"},
        ],
        references=[
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
        published_date=datetime(2021, 12, 10, 0, 0, tzinfo=UTC),
        is_known_exploited=True,
    ),
]
