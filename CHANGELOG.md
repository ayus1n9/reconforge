# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
