# ReconForge

**Intelligent Network Attack-Surface Mapping, Exposure Assessment & Security Intelligence Platform**

ReconForge is a modular, security-conscious network attack-surface mapping and exposure assessment platform. Designed for security engineers, SOC analysts, and vulnerability management teams, it transforms raw network discovery into a structured, evidence-backed security assessment.

---

## Key Capabilities (Phase 1 Foundation)

- **Asynchronous TCP Discovery Engine**:
  - High-performance asynchronous 3-way handshake scanner built on Python's standard `asyncio` primitives.
  - Bounded concurrency with `asyncio.Semaphore` ceiling to prevent system socket exhaustion and memory spikes.
  - Token-bucket rate limiting for strict bandwidth and probe regulation.
  - Granular port state classification: `OPEN`, `CLOSED`, `TIMEOUT`, `FILTERED`, `UNREACHABLE`, `ERROR`, and `NOT_SCANNED` (strictly distinguishing timeouts from confirmed filtered states).
- **Strict Authorization Boundary Enforcement**:
  - Non-bypassable allowlist model supporting IPv4/IPv6 addresses, CIDRs, and hostnames.
  - Pre-flight scope verification on every probe before socket allocation.
  - Built-in SSRF protection against cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`).
  - Safe defaults: public internet scanning disabled unless explicitly authorized.
- **DNS Pinning & TOCTOU Defense**:
  - Forward DNS resolution (A/AAAA) with automatic scope re-validation.
  - Pinned destination IP addresses preventing DNS rebinding attacks.
- **Modern CLI Interface**:
  - Typer CLI with Rich terminal formatting, interactive confirmation boundaries, progress telemetry, and structured JSON output.

---

## Quickstart & Installation

### Requirements
- Python 3.12+ (tested on Python 3.14)
- Linux / macOS / Windows

### Setup Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Basic CLI Usage

#### 1. System Information
```bash
reconforge version
```

#### 2. Execute an Authorized Scan
Scan specific ports on an authorized target:
```bash
reconforge scan 127.0.0.1 -p "80,443,8000-8080" --timeout 1.5 --concurrency 25
```

Output formatted as JSON for pipeline automation:
```bash
reconforge scan 127.0.0.1 -p "22,80,443" --yes --json
```

#### 3. Validate Scope Configuration
Validate an assessment scope YAML file:
```bash
reconforge validate-scope examples/sample-scope.yaml
```

---

## Testing & Quality Engineering

Run the test suite across unit, integration, and security boundaries:
```bash
pytest -v
```

Run code formatting and security linting:
```bash
ruff check .
```

---

## Ethical & Operational Boundaries
ReconForge is strictly an authorized assessment tool. It does **not** include exploit modules, denial-of-service payloads, brute-force engines, or evasion mechanisms. All scans require explicit authorization and operational scope limits.

---

## License
Apache-2.0. See `LICENSE` for details.
