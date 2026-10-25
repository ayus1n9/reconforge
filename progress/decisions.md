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
