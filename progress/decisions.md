# ReconForge Architecture Decision Records (ADRs)

## ADR-001: Technology Stack Selection
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Need a fast, reliable, reproducible stack for asynchronous network scanning, service fingerprinting, vulnerability intelligence correlation, reporting, and dashboard visualization.
- **Decision**:
  - **Core Language**: Python 3.14 (utilizing standard library `asyncio` for non-blocking I/O).
  - **CLI Framework**: Typer with Rich for structured terminal output.
  - **Data Modeling & Validation**: Pydantic v2.
  - **Persistence**: SQLAlchemy with SQLite (WAL mode) for zero-dependency local reliability.
  - **Nmap Integration**: Sandboxed subprocess execution with vector arguments (never `shell=True`) and hardened XML parsing (`defusedxml` / hardened `ElementTree`).
  - **API**: FastAPI.
  - **Frontend**: React 18, Vite, TypeScript, Tailwind CSS.
- **Consequences**: Minimal external infrastructure requirements, high performance, strict type safety, cross-platform portability.

## ADR-002: Scope Security & DNS Pinning Model
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Port scanning tools can easily become vectors for accidental out-of-scope scanning, SSRF against cloud metadata, or DNS rebinding (TOCTOU) attacks.
- **Decision**:
  - Scope is enforced strictly via allowlist (`allowed_targets`, `excluded_targets`, `allowed_ports`).
  - All hostnames are resolved forward (A/AAAA) immediately.
  - Resolved IP addresses are checked against the scope allowlist *before* any connection.
  - Socket connections bind directly to the verified IP address, never re-resolving hostnames per port probe.
  - Cloud metadata (e.g. `169.254.169.254`), loopback, and unapproved private subnets are blocked unless explicitly configured in lab scope.
- **Consequences**: Prevents DNS rebinding and SSRF bypasses at the architectural level.

## ADR-003: Non-Intrusive, Evidence-Based Assessment Philosophy
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Differentiating ReconForge from offensive exploit tools and naive port scanners.
- **Decision**:
  - No exploitation, no credential stuffing, no brute-forcing, no evasive packet crafting.
  - Every finding must be linked to observable evidence (e.g., protocol response, banner string, TLS cert field).
  - Explicit finding states: `INFORMATIONAL`, `POTENTIAL_EXPOSURE`, `POTENTIAL_VULNERABILITY`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `NEEDS_REVIEW`.
  - Distinguish between observation and conclusion: matching a product version to a CVE does not prove exploitability.
- **Consequences**: Professional, defensible security engineering suitable for SOCs and vulnerability management teams.

## ADR-004: Precise Port State Semantics (Non-Conflation of Timeouts)
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Many basic port scanners equate an unanswered probe with a "filtered" port. In real networking, an uncompleted handshake can be caused by network lag, silent host drop, routing drops, or congestion.
- **Decision**:
  - Differentiate `TIMEOUT` (inconclusive silence) from `FILTERED` (positive ICMP administratively prohibited or OS permission rejection).
  - Explicit states: `OPEN` (syn-ack), `CLOSED` (rst), `TIMEOUT` (timed out), `FILTERED` (admin drop), `UNREACHABLE` (host/net unreach), `ERROR` (socket exception), `NOT_SCANNED` (aborted prior to probe).
- **Consequences**: Findings and reporting remain scientifically accurate and defensible under audit.

## ADR-005: Resource Bounding Architecture
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Scanning CIDR ranges with unbounded concurrency can quickly exhaust system file descriptors (`EMFILE`), flood local networking buffers, or trigger IPS throttling.
- **Decision**:
  - Implement strict bounded concurrency via `asyncio.Semaphore(concurrency)`.
  - Implement token-bucket rate limiting via `AsyncTokenBucketRateLimiter(rate_per_second)`.
  - Max single CIDR expansion capped at 4,096 addresses to avoid memory exhaustion on wide CIDRs.
- **Consequences**: Guaranteed predictable CPU and memory profile, preventing DoS of the scanning host.

## ADR-006: Modular Protocol Probes vs Raw Port Inference
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Port numbers alone do not determine service identity (e.g. HTTP running on 8080/8443, SSH running on 2222, non-HTTP services running on 80/443).
- **Decision**:
  - Implement modular, non-intrusive protocol probes (`HTTPProbe`, `TLSProbe`, `SSHProbe`, `SMTPProbe`, `FTPProbe`, `DatabaseProbe`).
  - Prioritize probes based on common default ports for performance, but execute empirical protocol verification without assuming identity.
  - Confidence scoring must strictly correlate with actual evidence (`HIGH` = verified handshake & version, `MEDIUM` = verified handshake without version, `LOW` = weak heuristic, `UNKNOWN` = open port without protocol match).
- **Consequences**: Accurate attack-surface observations without false assumptions.

## ADR-007: Hardened Subprocess Execution and XXE-Safe XML Parsing
- **Date**: 2026-10-25
- **Status**: ACCEPTED
- **Context**: Executing external scanner binaries (Nmap) and parsing XML output introduces command injection, XXE, and resource exhaustion vulnerabilities.
- **Decision**:
  - Never execute shell wrappers (`shell=False`, argument vector execution only).
  - Enforce subprocess execution timeout and 10 MB maximum stdout buffer limit.
  - Parse XML output strictly using `defusedxml` to block external entity resolution (XXE) and recursive entity expansion bombs (Billion Laughs).
- **Consequences**: Secure and robust optional integration of established third-party scanning tools.

## ADR-008: Normalized Asset Identity by IP Address
- **Date**: 2026-10-26
- **Status**: ACCEPTED
- **Context**: In network attack-surface mapping, multiple distinct IP addresses frequently resolve from a single hostname (e.g., DNS round-robin, load balancers, CDNs), and a single IP may host multiple virtual hosts. Collapsing assets by hostname causes inventory corruption, while keying purely on arbitrary strings loses referential integrity.
- **Decision**:
  - Assets are uniquely keyed and identified in the repository and database by canonical IP address (`AssetRecord.ip_address`).
  - Observed hostnames are stored as an array associated with that IP address (`observed_hostnames`), never merged across different IP addresses.
  - Services are uniquely constrained by `(asset_id, port, protocol)`.
- **Consequences**: Deterministic, corruption-free inventory tracking across repeated assessment cycles.

## ADR-009: Strict Untrusted Snapshot Ingestion Defenses
- **Date**: 2026-10-26
- **Status**: ACCEPTED
- **Context**: Importing snapshot JSON files from untrusted environments or third-party operators can be an attack vector for SQL injection, buffer overruns, command injection, terminal ANSI escape pollution, or schema degradation.
- **Decision**:
  - All incoming snapshot documents must pass rigorous Pydantic schema validation (`AssessmentSnapshot`, `SnapshotAsset`, `SnapshotService`).
  - IP addresses are strictly validated with `parse_ip_or_network()` to ensure valid IPv4/IPv6 addresses.
  - Ports are bounded by `ge=1, le=65535`.
  - Service banners are stripped of ANSI escape sequences (`\x1b`), control characters, and null bytes before database insertion.
  - Snapshot schema versions are enforced, rejecting mismatched or unsupported formats.
- **Consequences**: Safe offline sharing and archiving of assessment data without compromising the host or database.

## ADR-010: Declarative Exposure Rule Engine with Transport Prerequisite Isolation
- **Date**: 2026-10-27
- **Status**: ACCEPTED
- **Context**: Evaluating attack-surface exposures across varying ports and services requires declarative matching rules without hardcoding detection heuristics. Naively evaluating transport protocols (`tcp`/`udp`) as positive matching criteria causes false positives when combined with disjunctive (`require_all=False`) evaluation.
- **Decision**:
  - Treat transport protocol (`tcp`, `udp`) strictly as a prerequisite gate rather than an exposure trigger.
  - Implement declarative rules with structured conditions: `ports`, `service_names`, `products`, `version_pattern`, `banner_pattern`, and `tls_conditions`.
  - Cap regular expression length at 500 characters and pre-compile with `re.compile()` to block catastrophic backtracking (ReDoS).
  - Enforce safe YAML parsing via `yaml.safe_load()` and bounded file size limits (1 MB) for user-supplied rule files.
- **Consequences**: Zero code execution risks, high evaluation throughput, and robust resistance to false positives.

## ADR-011: Defensible Finding Lifecycle States & Evidence Linking
- **Date**: 2026-10-27
- **Status**: ACCEPTED
- **Context**: Port scanning observations should not be conflated with confirmed vulnerabilities or active exploits without empirical proof. Hiring managers and security teams require distinct classifications between exposure, potential vulnerability, and confirmed issue.
- **Decision**:
  - Establish explicit finding lifecycle states: `INFORMATIONAL`, `POTENTIAL_EXPOSURE`, `POTENTIAL_VULNERABILITY`, `CONFIRMED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `NEEDS_REVIEW`.
  - Open services on sensitive ports (e.g. Redis on 6379, MySQL on 3306) are classified as `POTENTIAL_EXPOSURE` rather than confirmed vulnerabilities unless direct proof of unauthorized access is observed.
  - Every finding links back to an evidence payload containing the exact observation parameters (target IP, port, protocol, response latency, banner snippet, and matched criteria).
- **Consequences**: High-fidelity security intelligence suitable for enterprise SOC triage, compliance auditing, and risk prioritization.

## ADR-012: Calibrated Vulnerability Correlation & Distribution Backport Detection
- **Date**: 2026-10-29
- **Status**: ACCEPTED
- **Context**: Naive vulnerability scanners match banner version strings against CVE ranges and report false-positive "Critical" vulnerabilities. Linux distributions (Debian, Ubuntu, RHEL, CentOS) routinely backport security fixes into older upstream packages without incrementing the upstream version string (e.g. `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`). Reporting these as unpatched critical vulnerabilities erodes credibility.
- **Decision**:
  - Implement a 4-tier calibrated confidence model:
    - `STRONG_CANDIDATE`: Exact vendor, product, and version boundary matched without packaging ambiguity.
    - `MANUAL_VERIFICATION_REQUIRED`: Version falls in affected upstream range, but distribution package indicators (Ubuntu, Debian, RHEL, etc.) are detected, requiring package changelog inspection.
    - `POSSIBLE_MATCH`: Product matches, but version is ambiguous or falls within an unconfirmed range.
    - `INSUFFICIENT_EVIDENCE`: Product identified, but version is omitted or wild-carded.
  - Require both vendor and product match against CPE criteria to prevent vendor-level cross-product false positives (e.g., Apache HTTP Server matching Apache Log4j).
- **Consequences**: Defensible, accurate vulnerability intelligence that security engineers and auditors can trust without noise.

## ADR-013: Offline-First Vulnerability Caching & Bounded NVD Synchronization
- **Date**: 2026-10-29
- **Status**: ACCEPTED
- **Context**: Cybersecurity teams frequently operate in isolated, air-gapped, or restrictive test labs without Internet access. Querying remote APIs like NIST NVD during scans can stall assessments, leak target intelligence, or fail due to strict public API rate limits (5 req/30s).
- **Decision**:
  - Local-first architecture: maintain an internal SQLite `cve_cache` table pre-seeded with high-impact curated reference CVEs (regreSSHion, Terrapin, Apache traversal, Log4Shell, Redis sandbox escape, vsftpd backdoor).
  - Bounded asynchronous NVD client with token-bucket rate limiting (5 req/30s unauthenticated, 50 req/30s with API key), exponential backoff on HTTP 429/503, strict timeout (15s), and 5 MB maximum response payload limits.
  - Transparent fallback: when offline or when network requests fail, the correlator automatically relies on local SQLite cache without halting scans.
- **Consequences**: Air-gapped reliability, zero-network scanning support, protection against memory exhaustion, and resilient threat intelligence retrieval.

## ADR-014: Explainable Attack-Surface Scoring & Risk Prioritization
- **Date**: 2026-10-30
- **Status**: ACCEPTED
- **Context**: Security assessments often output arbitrary severity counts or opaque numerical scores that cannot be explained or defended in executive or SOC review. Furthermore, averaging asset scores across a large network allows critical servers to be obscured by dozens of clean endpoints.
- **Decision**:
  - Implement a transparent, mathematical attack-surface scoring algorithm bounded strictly between 0.0 and 100.0:
    $$\text{Raw Score} = (S_{exp} + S_{findings}) \times W_{crit} \times M_{threat}$$
  - Calculate Network Exposure Base ($S_{exp}$) from open port count (1.5 pts/port, max 15.0) and sensitive exposed protocols (database +4.0, cleartext +3.0, remote management +2.0), capped at 25.0 pts.
  - Weight active findings ($S_{findings}$) by severity (Critical: 25.0, High: 15.0, Medium: 7.0, Low: 2.0, Info: 0.5) and scale by finding lifecycle state modifiers (`confirmed`: 1.0, `potential_vulnerability`: 0.9, `potential_exposure`: 0.75, `needs_review`: 0.6, `false_positive`: 0.0).
  - Apply Asset Criticality Multiplier ($W_{crit}$): Critical (1.5x), High (1.2x), Medium (1.0x), Low (0.8x).
  - Apply Threat Intelligence Multiplier ($M_{threat}$): CISA KEV exploitation (1.35x), Remote Code Execution (1.20x).
  - Emit an auditable list of human-readable mathematical steps (`component_explanations`) for every asset evaluation.
  - Compute overall estate posture using a max-anchored composite ($0.6 \times \max + 0.4 \times \text{mean}$) to guarantee that catastrophic vulnerabilities on critical assets are never diluted by clean nodes.
  - Map deterministic remediation urgency into 5 clear tiers: P1 (Immediate), P2 (High Urgency), P3 (Medium Urgency), P4 (Low Urgency), P5 (Informational).
- **Consequences**: Explainable, defensible risk metrics aligned with real-world enterprise vulnerability management programs.

## ADR-015: Multi-Format Report Generation Security (CWE-1236 & CWE-79)
- **Date**: 2026-10-30
- **Status**: ACCEPTED
- **Context**: Security scanning reports consume untrusted external data (network banners, HTTP titles, hostnames, reverse DNS records). When exported to CSV, unescaped formulas (`=cmd|...`) execute arbitrary code in Excel (CWE-1236). When exported to HTML, unsanitized banners or target descriptions execute stored XSS (CWE-79). Furthermore, external CDN dependencies (fonts, stylesheets, JS libraries) break in air-gapped security enclaves and introduce supply chain risks.
- **Decision**:
  - Fortify CSV generation (`sanitize_csv_cell`): Prepend a single quote (`'`) to any cell beginning with dangerous formula or command characters (`=`, `+`, `-`, `@`, `\t`, `\r`).
  - Strict HTML escaping: Escape all scanner outputs, target IPs, hostnames, titles, and descriptions using `html.escape(..., quote=True)` prior to interpolation.
  - 100% self-contained HTML: Zero external CDN stylesheets, scripts, or images. Embed all typography, color palettes, badges, responsive CSS, and layout styling directly within an inline `<style>` block.
- **Consequences**: Safe, verifiable reporting documents that can be safely viewed in spreadsheet software and web browsers without code execution risks, even in completely air-gapped defense enclaves.



