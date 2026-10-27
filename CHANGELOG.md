# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
