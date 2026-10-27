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

