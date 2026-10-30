# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-10-30

### Added
- **Explainable Attack-Surface Scoring Engine (`AttackSurfaceCalculator`)**:
  - Transparent, mathematical scoring algorithm generating defensible risk scores bounded strictly between 0.0 and 100.0.
  - Multi-factor risk formula: `Raw Score = (Exposure_Base + Findings_Subtotal) * Criticality_Weight * Threat_Multiplier`.
  - Network exposure baseline factoring open transport ports (1.5 pts per port, capped at 15.0) and sensitive protocols (database services +4.0 pts, cleartext protocols +3.0 pts, remote management +2.0 pts), with total exposure capped at 25.0 pts.
  - Security findings subtotal weighting confirmed findings (Critical: 25.0, High: 15.0, Medium: 7.0, Low: 2.0, Informational: 0.5) scaled by lifecycle state modifiers (`confirmed`: 1.0, `potential_vulnerability`: 0.9, `potential_exposure`: 0.75, `needs_review`: 0.6, `false_positive`: 0.0).
  - Asset criticality factor: Critical (1.5x), High (1.2x), Medium (1.0x), Low (0.8x).
  - Threat intelligence multiplier: Active CISA KEV exploitation (1.35x), Remote Code Execution (1.20x).
  - Complete, step-by-step mathematical explanation trail (`component_explanations`) embedded in every calculation for SOC auditability.
  - Overall estate posture calculation using max-anchored composite aggregation (`0.6 * max + 0.4 * mean`) preventing severe asset risks from being diluted by clean nodes.
- **Deterministic Risk Prioritization Engine (P1 to P5)**:
  - Deterministic priority assignment mapped directly to remediation urgency:
    - `P1 (Immediate)`: Actively exploited vulnerabilities (CISA KEV) or Critical severity issues on High/Critical assets.
    - `P2 (High Urgency)`: Critical severity on Medium/Low assets, High severity exposures, or exposed database services.
    - `P3 (Medium Urgency)`: Cleartext protocols (Telnet, HTTP, FTP) or legacy cryptographic configurations.
    - `P4 (Low Urgency)`: Minor service misconfigurations or general network hygiene issues.
    - `P5 (Informational)`: Software version disclosures or routine inventory observations.
- **Multi-Format Report Generation Engine (`ReportEngine`)**:
  - `JSONReportGenerator`: Structured, schema-validated JSON report export suitable for SIEM, SOAR, and automated CI/CD pipeline consumption.
  - `MarkdownReportGenerator`: GitHub Flavored Markdown executive summary, urgency breakdown tables, asset inventory matrix, detailed findings catalog, and actionable remediation roadmap.
  - `CSVReportGenerator`: Tabular export fortified against spreadsheet formula injection attacks (CWE-1236) by neutralizing dangerous control characters (`=`, `+`, `-`, `@`, `\t`, `\r`) with single-quote escaping.
  - `HTMLReportGenerator`: Standalone, self-contained HTML5 report with zero external CDN dependencies, embedded CSS design system, color-coded risk meter, responsive tables, and strict HTML escaping (`html.escape`) to prevent cross-site scripting (CWE-79).
- **New CLI Commands & Scan Integration**:
  - `reconforge score <assessment_id> [--detail]`: Calculate and display aggregate posture and detailed asset attack-surface scores.
  - `reconforge report generate <assessment_id> [--format html|json|markdown|csv] [--output path]`: Build and export comprehensive reports.
  - `reconforge report export <assessment_id> [--format html|json|markdown|csv] [--output path]`: Export reports directly to disk.
  - `reconforge scan`: Integrated real-time posture panel output and `--json` format enrichment with `risk_posture`.
- **Database Model Enhancements**:
  - Added `risk_score` and `risk_breakdown` columns to `AssetRecord`.
  - Added `risk_score` and `risk_posture` columns to `AssessmentRecord`.
- **Testing & Security**:
  - 28 new automated tests added (121 total passing tests across unit, integration, and security suites).
  - Zero Bandit static security issues across 7,244 LOC.
  - Complete coverage for CWE-1236 formula injection and CWE-79 XSS prevention.

## [0.5.0] - 2026-10-30

### Added
- **Common Platform Enumeration (CPE 2.3) Engine (`CPE`)**:
  - Full implementation of NIST IR 7695 CPE 2.3 formatting (`cpe:2.3:a:vendor:product:version:...`) and legacy CPE 2.2 URI compatibility.
  - Automatic component sanitization stripping whitespace and non-standard characters.
  - Automated service attribute derivation (`from_service()`) mapping network server software (OpenSSH, Apache, Nginx, Redis, MySQL, PostgreSQL, vsftpd, Docker, etc.) to canonical vendor and product identifiers.
- **Semantic Version Matching & Distro-Backport Detection (`version_matcher.py`)**:
  - PEP 440 and loose version comparator for irregular software release numbering schemes (e.g. `8.9p1`, `2.4.49`, `10.2p1`).
  - Boundary validation evaluating NVD version criteria (`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`, `exactVersion`).
  - Distribution backport pattern detector identifying Debian, Ubuntu, RHEL, CentOS, Amazon Linux, and SUSE package markers in banners and version strings.
- **Curated Built-in CVE Dataset (`BUILTIN_CVES`)**:
  - Offline vulnerability intelligence for high-profile network services:
    - `CVE-2024-6387`: OpenSSH regreSSHion unauthenticated remote code execution (CVSS 8.1, High).
    - `CVE-2023-48795`: SSH transport protocol Terrapin prefix truncation attack (CVSS 5.9, Medium).
    - `CVE-2018-15473`: OpenSSH user enumeration via authentication response timing (CVSS 5.3, Medium).
    - `CVE-2021-41773`: Apache HTTP Server path traversal and file disclosure (CVSS 7.5, High).
    - `CVE-2021-42013`: Apache HTTP Server path traversal and RCE incomplete fix (CVSS 9.8, Critical).
    - `CVE-2022-0543`: Redis Lua sandbox escape and RCE (CVSS 10.0, Critical).
    - `CVE-2011-2523`: vsftpd 2.3.4 Smiley backdoor execution (CVSS 9.8, Critical).
    - `CVE-2021-44228`: Apache Log4j Log4Shell JNDI RCE (CVSS 10.0, Critical).
  - Complete metadata including CVSS v3 score and vector, CWE IDs, affected CPE configurations, version boundaries, vendor advisory URLs, and CISA Known Exploited Vulnerabilities (KEV) catalog status.
- **Offline-First SQLite Vulnerability Cache (`VulnerabilityCache`)**:
  - Persistent SQLite storage in `cve_cache` table with indexes on CVE ID and cached timestamp.
  - Automatic seeding of curated built-in intelligence on initial run.
  - Multi-attribute search supporting keywords, CPE product, minimum CVSS base score, severity level, and CISA KEV listing.
- **Asynchronous NIST NVD Client (`AsyncNVDClient`)**:
  - Asynchronous client for NIST NVD REST API v2.0 (`services.nvd.nist.gov/rest/json/cves/2.0`).
  - Token-bucket rate limiter enforcing 5 requests per 30 seconds for public API access and 50 requests per 30 seconds with API key.
  - Exponential backoff with jitter on HTTP 429 and 503 responses.
  - Security-hardened HTTP fetching: 15-second timeout, asynchronous execution in thread pool, and 5 MB maximum payload size limit.
  - Seamless offline fallback: automatically returns local cache items on network error or in offline mode.
- **Evidence-Calibrated Vulnerability Correlator (`VulnerabilityCorrelator`)**:
  - Calibrated 4-tier match confidence scoring:
    - `STRONG_CANDIDATE`: Unambiguous version match within affected range on upstream software.
    - `MANUAL_VERIFICATION_REQUIRED`: Version falls in vulnerable upstream range, but distribution packaging indicators (e.g. `Ubuntu-3ubuntu0.10`) suggest security patches were backported.
    - `POSSIBLE_MATCH`: Product matches, but version string is ambiguous or falls within an unconfirmed range.
    - `INSUFFICIENT_EVIDENCE`: Product identified, but version is absent or wild-carded.
  - Dual vendor and product matching to eliminate vendor-level false positives (e.g. Apache HTTP Server matching Log4j).
  - Assessment correlation integration persisting findings to database with mapped lifecycle states (`POTENTIAL_VULNERABILITY`, `NEEDS_REVIEW`, `POTENTIAL_EXPOSURE`, `INFORMATIONAL`).
- **New CLI Commands & Scan Integration**:
  - `reconforge cve search <query>`: Search cached vulnerability intelligence with filters.
  - `reconforge cve show <cve_id>`: Display comprehensive vulnerability metrics, CVSS vector, and references.
  - `reconforge cve list-builtin`: Tabular overview of curated offline CVE intelligence dataset.
  - `reconforge cve correlate`: Correlate inventoried services with vulnerability intelligence and classify confidence tiers.
  - `reconforge scan --correlate-cves`: Integrated network discovery, exposure assessment, and CVE correlation in a single command.
- **Testing & Security**:
  - 24 new automated tests added (93 total passing tests across unit, integration, and security boundaries).
  - Bandit static security analysis clean (0 issues across 5,922 LOC).
  - Ruff formatting and linting 100% clean.

## [0.4.0] - 2026-10-27

### Added
- **Declarative Exposure Assessment Engine (`ExposureEngine`)**:
  - Rule evaluation pipeline evaluating discovered open ports, services, banners, and TLS metadata against declarative security rules without active exploitation payloads.
  - Multi-condition rule matching supporting exact ports, port lists, service names, software product names, version regex patterns, raw banner regex patterns, and cryptographic TLS parameters (`is_expired`, `is_self_signed`, legacy protocol negotiation).
  - Configurable matching modes (`require_all=True` for strict multi-factor criteria, `require_all=False` for broad exposure heuristics).
  - Automated finding deduplication based on `(assessment_id, asset_id, service_id, rule_id)`.
- **Comprehensive Built-In Rulebook (`BUILTIN_RULES`)**:
  - Cleartext Protocol Rules: Telnet (`EXP-CLEARTEXT-TELNET`), FTP (`EXP-CLEARTEXT-FTP`), HTTP (`EXP-CLEARTEXT-HTTP`).
  - Database Exposure Rules: Redis (`EXP-DB-REDIS`), MySQL/MariaDB (`EXP-DB-MYSQL`), PostgreSQL (`EXP-DB-POSTGRES`), MongoDB (`EXP-DB-MONGODB`), Elasticsearch (`EXP-DB-ELASTIC`).
  - Administrative & Dangerous Management Interfaces: SSH (`EXP-MGMT-SSH`), Docker Engine Daemon TCP API (`EXP-MGMT-DOCKER`), Kubernetes Control Plane (`EXP-MGMT-K8S`), VNC (`EXP-MGMT-VNC`), RDP (`EXP-MGMT-RDP`).
  - Cryptographic & TLS Rules: Expired X.509 certificates (`EXP-TLS-EXPIRED`), Self-signed certificates (`EXP-TLS-SELFSIGNED`), Obsolete TLS protocol versions (`EXP-TLS-LEGACY`).
  - Information Disclosures: Granular server and OS banner disclosure (`EXP-INFO-BANNER`).
- **Custom YAML Rule Loader & Validator (`custom_rules.py`)**:
  - Safe YAML ingestion using `yaml.safe_load` preventing arbitrary code execution.
  - File size bounds (1 MB maximum per rule file) and regex length limits (500 characters) to mitigate ReDoS and resource exhaustion.
  - Directory scanning support (`load_rules_from_directory`) with non-terminating warning logging for malformed rules.
- **Enhanced CLI Commands**:
  - `reconforge assess <assessment_id> [--rules-dir <path>]`: Evaluate exposure rules against historical or newly imported assessments.
  - `reconforge findings list [--assessment-id] [--severity] [--state]`: Tabular display of findings with severity badge colors, asset IP, port, and state.
  - `reconforge findings show <finding_id>`: Detailed panel view displaying title, rule ID, severity badge, state, description, evidence JSON, and actionable remediation guidance.
  - `reconforge findings update <finding_id> <state>`: Transition finding lifecycle state (`confirmed`, `false_positive`, `accepted_risk`, `needs_review`).
  - `reconforge rules list [--category] [--severity]`: Tabular overview of registered built-in and custom rules.
  - `reconforge rules validate <file.yaml>`: Validate user-created YAML rules against schema.
  - Integrated scan evaluation: `reconforge scan` automatically evaluates exposure rules on open ports by default (controllable via `--assess/--no-assess`).
- **Testing & Security**:
  - 16 new automated tests added (69 total passing tests across unit, integration, and security boundaries).
  - Bandit static security analysis clean (0 issues across 4,399 LOC).
  - Ruff formatting and linting 100% verified.

## [0.3.0] - 2026-10-26

### Added
- **Normalized Asset Inventory & Relational Data Model**:
  - `DatabaseManager`: SQLite storage engine configured with `PRAGMA foreign_keys=ON;`, `PRAGMA synchronous=NORMAL;`, and `PRAGMA journal_mode=WAL;` for atomic concurrency and relational referential integrity.
  - Relational schema with SQLAlchemy 2.0 ORM:
    - `AssetRecord`: Normalized network asset keyed by canonical IP address; tracks hostnames (JSON array), asset type, discovery sources, and monotonic UTC observation timestamps (`first_observed_at`, `last_observed_at`).
    - `ServiceRecord`: Normalized exposed network service with composite unique constraint `uq_asset_port_proto` (`asset_id`, `port`, `protocol`), confidence elevation, banner snippet sanitization, and candidate CPEs.
    - `AssessmentRecord`: Security assessment run metadata tracking execution parameters, scanner version, run state, and aggregate probe coverage metrics.
    - `FindingRecord`: Traceable security finding schema tracking rule ID, severity, state, confidence, title, description, and remediation guidance.
  - `AssetRepository`: Domain repository ensuring assets are indexed strictly by IP address without merging separate hosts sharing a domain or CNAME, providing atomic scan recording and history retrieval.
- **Assessment Snapshot Engine (`SnapshotManager`)**:
  - Full versioned export of assessment scopes, assets, services, and findings into schema-validated JSON (`AssessmentSnapshot`).
  - Strict Pydantic ingestion validation: rejects malformed JSON, out-of-range ports, and unvalidated IP strings (preventing SQL and command injection).
  - Terminal escape sequence stripping and null-byte sanitization on all imported banner text.
- **Enhanced CLI Commands**:
  - `reconforge assets list`: Rich tabular display of inventoried assets, exposed ports, criticality, and last seen timestamps.
  - `reconforge assets show <id_or_ip>`: Detailed panel inspection for a single asset with full service history and banner details. Supports UUID prefix matching.
  - `reconforge assessments list`: Chronological list of historical assessment runs, status, and open port counts.
  - `reconforge snapshot export <assessment_id> [--output file]`: Export versioned JSON assessment snapshots.
  - `reconforge snapshot import <snapshot_path>`: Validate and ingest untrusted assessment snapshots with full referential integrity.
  - Automatic scan persistence: `reconforge scan` automatically saves assessment and discovered services into the inventory database unless `--no-save` is specified.
- **Testing & Security**:
  - 11 new tests added (53 total passing tests) covering repository identity separation, timestamp monotonicity, confidence elevation, snapshot round-trip, and untrusted import injection resistance.
  - Bandit static security scan clean (0 issues across 3,131 LOC).
  - Ruff formatting and linting 100% verified.

## [0.2.0] - 2026-10-25

### Added
- **Modular Service Fingerprinting Probes**:
  - `HTTPProbe`: RFC 9112 HEAD/GET request parsing of status lines, `Server`, and `X-Powered-By` headers. Detects HTTPS redirections.
  - `TLSProbe`: Non-intrusive SSL/TLS handshake extracting protocol versions, cipher suites, certificate subject/issuer CNs, validity dates, SANs, and self-signed/expired flags.
  - `SSHProbe`: RFC 4253 protocol identification banner parser extracting software names, versions (e.g. OpenSSH), OS comments, and candidate CPEs.
  - `SMTPProbe`: RFC 5321 greeting banner parser for MTAs (Postfix, Exim, Sendmail, Exchange).
  - `FTPProbe`: RFC 959 greeting parser for FTP daemons (vsftpd, ProFTPD, Pure-FTPd).
  - `DatabaseProbe`: Safe listener identification for Redis (RESP `PING`), MySQL/MariaDB (initial server handshake packet), and PostgreSQL (`SSLRequest`).
- **Service Detection Engine (`ServiceDetector`)**:
  - Orchestrates probes based on port defaults and heuristic fallbacks without assuming service identity based merely on port numbers.
  - Calibrated evidence-based confidence model (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`).
- **Hardened Nmap Subprocess Adapter (`NmapAdapter`)**:
  - Sandboxed subprocess execution (`shell=False`) with conservative service arguments (`-sT -sV --version-light`).
  - Execution duration limits and 10 MB stdout size bounding.
  - Hardened XML parsing with `defusedxml` to block XXE attacks and entity expansion bombs.
  - Normalizes Nmap service entries into internal `ServiceFingerprint` models preserving source attribution (`source=nmap`).
- **Enhanced CLI & Rich Telemetry**:
  - Added `--fingerprint / --no-fingerprint` and `--use-nmap` CLI options.
  - Rich table displays Service, Product, Version, Confidence, and Latency columns.
- **Testing & Security**:
  - Expanded test suite to 42 automated tests (unit, integration, and security tests).
  - Clean Bandit security analysis and Ruff linting conformance.

## [0.1.0] - 2026-10-25

### Added
- **Asynchronous TCP Discovery Engine**:
  - `AsyncTCPScanner` utilizing Python's `asyncio.open_connection` with strict socket cleanup.
  - Bounded concurrency with `asyncio.Semaphore` ceiling.
  - Token-bucket rate limiting via `AsyncTokenBucketRateLimiter`.
  - Granular port state distinctions: `OPEN`, `CLOSED`, `TIMEOUT`, `FILTERED`, `UNREACHABLE`, `ERROR`, `NOT_SCANNED`.
- **Authorization & Boundary Enforcement**:
  - `ScopeManager` enforcing strict allowlists for IPv4, IPv6, CIDRs, and RFC 1123 hostnames.
  - Default rejection of public internet targets (`allow_public_targets: False`).
  - SSRF protection rejecting cloud metadata IP addresses (`169.254.169.254`, `fd00:ec2::254`).
  - CIDR expansion bounds (`MAX_EXPANDED_CIDR_HOSTS = 4096`).
- **DNS Resolution & Pinning**:
  - Forward DNS resolver (`DNSResolver`) resolving A and AAAA records.
  - Pre-scan validation of all resolved IPs to neutralize DNS rebinding (TOCTOU).
  - Pinned destination IP addresses for socket connections.
- **Command-Line Interface**:
  - Typer CLI with Rich terminal tables and progress telemetry (`scan`, `validate-scope`, `version`).
  - Interactive scope confirmation guard before executing network probes.
  - Machine-readable `--json` output format.
- **Testing & Security Suite**:
  - 27 unit, integration, and security tests covering socket states, cancellation, scope bypasses, and rate limiting.
  - Clean Bandit security analysis and Ruff linting conformance.
