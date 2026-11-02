# ReconForge

<p align="center">
  <img src="web/public/shield.svg" alt="ReconForge Logo" width="100" height="100" />
</p>

<h3 align="center">Intelligent Network Attack-Surface Mapping, Exposure Assessment & Security Intelligence Platform</h3>

<p align="center">
  <a href="https://github.com/ayus1n9/reconforge/releases/tag/v1.0.0"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg?style=flat-square" alt="Version 1.0.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg?style=flat-square" alt="License Apache-2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12%2B-blue.svg?style=flat-square" alt="Python 3.12+"></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-168%20passed%20%7C%20100%25-brightgreen.svg?style=flat-square" alt="Tests 100% Passed"></a>
  <a href="#"><img src="https://img.shields.io/badge/security-Bandit%200%20Issues-brightgreen.svg?style=flat-square" alt="Bandit Security Clean"></a>
  <a href="#"><img src="https://img.shields.io/badge/code%20style-Ruff-000000.svg?style=flat-square" alt="Code Style Ruff"></a>
</p>

---

## Overview

**ReconForge** is an enterprise-grade, defensive network attack-surface mapping, exposure assessment, and security intelligence platform designed for security engineers, SOC analysts, and vulnerability management teams.

Unlike primitive port scanners or aggressive offensive tools, ReconForge bridges raw packet discovery and actionable defensive intelligence. It transforms empirical network observations into defensible, mathematically grounded security posture assessments with verifiable evidence chains, explainable risk scoring, automated change detection, and an embedded modern React dashboard.

---

## Key Capabilities & Architecture

```
                                  RECONFORGE PLATFORM
                                 
   [ CLI Command Line ]        [ FastAPI REST Service ]       [ Embedded Web UI ]
       (Typer/Rich)                (OpenAPI / Swagger)          (React 18 / Vite)
            │                               │                          │
            └───────────────────────┬───────┴──────────────────────────┘
                                    │
    ┌───────────────────────────────┴───────────────────────────────┐
    │                    CORE PLATFORM ENGINE                       │
    ├───────────────────────────────────────────────────────────────┤
    │  • Scope Enforcer & SSRF Guard (Non-bypassable allowlists)    │
    │  • DNS Pinning & TOCTOU Defense (Forward A/AAAA resolution)   │
    │  • Token-Bucket Rate Limiter & Concurrency Semaphore Ceiling   │
    ├───────────────────────────────┬───────────────────────────────┤
    │      DISCOVERY SUBSYSTEM      │      ASSESSMENT SUBSYSTEM     │
    ├───────────────────────────────┼───────────────────────────────┤
    │  • Async TCP 3-Way Handshake  │  • Declarative Exposure Rules │
    │  • Granular Port States       │  • Rule Engine (10+ Builtin)  │
    │  • Modular Protocol Probes    │  • Custom YAML Rule Loader    │
    │  • Nmap Subprocess Adapter    │  • Finding Lifecycle States   │
    │  • DefusedXML Safe Parser     │  • Evidence Provenance Chains │
    ├───────────────────────────────┼───────────────────────────────┤
    │    INTELLIGENCE & SCORING     │     DIFFING & AUDIT EXPORT    │
    ├───────────────────────────────┼───────────────────────────────┤
    │  • NVD CVE 2.0 API Client     │  • Coverage-Aware Differencer │
    │  • SQLite TTL Vulnerability Cache│• Genuine vs Scope Drift    │
    │  • CPE 2.3 Formatter & Matching│• Executive Briefing Narrative│
    │  • Max-Anchored Risk Scoring  │  • Air-Gapped JSON Snapshots  │
    │  • Criticality & Exploit Multi│  • HTML (CSP), Markdown, CSV  │
    └───────────────────────────────┴───────────────────────────────┘
```

### 1. Reliable Network Discovery
- **Asynchronous TCP Engine**: High-performance connect scanner with bounded concurrency (`asyncio.Semaphore`) and token-bucket probe regulation.
- **Defensible State Semantics**: Explicitly distinguishes `OPEN` (syn-ack), `CLOSED` (rst), `TIMEOUT` (inconclusive silence), and `FILTERED` (ICMP prohibited).
- **Service & Version Fingerprinting**: Probes HTTP, TLS/SSL, SSH, SMTP, FTP, MySQL, Redis, and PostgreSQL with banner sanitization and CPE 2.3 formulation.
- **Hardened Subprocess Nmap Adapter**: Vector arguments (never `shell=True`) and hardened `defusedxml` parsing protecting against XXE and Billion Laughs bombs.

### 2. Authorization Boundary & Defensive Controls
- **Non-Bypassable Scope Allowlist**: Strict enforcement of IPv4, IPv6, CIDR blocks, hostnames, and port ranges.
- **SSRF & Cloud Metadata Defense**: Built-in, non-overridable blocking for cloud metadata services (`169.254.169.254`, `fd00:ec2::254`).
- **DNS Pinning**: Immediate forward resolution and IP binding preventing DNS rebinding (TOCTOU) exploits.

### 3. Declarative Exposure & Security Intelligence
- **Rule-Based Exposure Engine**: Evaluates exposed administrative interfaces, outdated protocols, unencrypted transport, unauthenticated databases, and IoT services.
- **CVE & CPE Correlation**: Local SQLite cache with TTL expiration correlating discovered CPEs against the National Vulnerability Database (NVD).
- **Explainable Risk Scoring**: Mathematical composite scoring (0.0 to 100.0) with maximum-anchored base, sublinear accumulation, asset criticality modifiers, and CISA KEV exploit weighting.

### 4. Coverage-Aware Differencing & Continuous Auditing
- **Semantic Drift Detection**: Distinguishes genuine security fixes from scan omissions (`DEFINITIVE` vs `UNCERTAIN_SCOPE_MISMATCH` vs `UNCERTAIN_REACHABILITY`).
- **Software Version Evolution**: Automatically tracks software upgrades, downgrades, and confidence drift across assessment cycles.
- **Multi-Format Export**: Generates self-contained interactive HTML reports (hardened CSP), executive Markdown summaries, CSV matrices, and air-gapped JSON snapshots.

### 5. Dual-Interface Experience: API & Embedded Dashboard
- **FastAPI REST Service**: Programmatic access with OpenAPI/Swagger docs, constant-time API key auth, background scan orchestration, and cancellation.
- **Self-Contained Web Dashboard**: Single-page application built with React 18, TypeScript, Tailwind CSS, and Recharts, **bundled directly into the Python wheel package**.

---

## Quickstart & Installation

### Requirements
- **Python**: 3.12 or higher (tested on 3.12, 3.13, 3.14).
- **Operating System**: Linux, macOS, or Windows.
- **Optional**: Nmap (for optional deep XML scanning; native TCP scanner works out of the box with zero dependencies).

### Installation via Pip

Install directly from the wheel distribution:
```bash
pip install dist/reconforge-1.0.0-py3-none-any.whl
```

Or install in development mode from repository source:
```bash
git clone https://github.com/ayus1n9/reconforge.git
cd reconforge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify the installation and runtime environment:
```bash
reconforge version
```

---

## Command-Line Interface (CLI) Guide

ReconForge features an intuitive, unified CLI powered by Typer and Rich.

### System Diagnostics
```bash
# Rich terminal diagnostics panel
reconforge version

# Machine-readable diagnostic JSON for automation
reconforge version --json
```

### Scope Validation
Validate an assessment scope YAML configuration before scanning:
```bash
reconforge validate-scope examples/sample-scope.yaml
```

### Network Discovery Scan
```bash
# Fast scan against authorized targets
reconforge scan 127.0.0.1 -p "80,443,8000-8080" --timeout 1.5 --concurrency 25 --save

# Autonomous non-interactive execution with JSON output
reconforge scan 192.168.1.0/24 -p "22,80,443" --yes --json
```

### Exposure Assessment & Risk Scoring
```bash
# Evaluate exposure rules against an assessment run
reconforge assess <ASSESSMENT_ID>

# Compute explainable risk posture score
reconforge score <ASSESSMENT_ID>
```

### Baseline Differencing
```bash
# Compare two database assessments
reconforge diff <BASE_ASSESSMENT_ID> <TARGET_ASSESSMENT_ID>

# Compare two offline JSON snapshots
reconforge diff-snapshots base_snapshot.json target_snapshot.json
```

### Report Generation & Snapshot Export
```bash
# Generate self-contained HTML audit report
reconforge report <ASSESSMENT_ID> --format html --output report.html

# Generate executive Markdown briefing
reconforge report <ASSESSMENT_ID> --format markdown --output summary.md

# Export point-in-time assessment snapshot
reconforge snapshot export <ASSESSMENT_ID> --output baseline.json
```

### Launch Web Dashboard & REST Service
```bash
# Launches the local FastAPI server and serves the bundled React UI
reconforge serve --host 127.0.0.1 --port 8000
```
Open your browser to:
- **Interactive Web Dashboard**: `http://127.0.0.1:8000/ui`
- **Swagger / OpenAPI Documentation**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc Documentation**: `http://127.0.0.1:8000/redoc`

---

## Web Dashboard Modules

The embedded Single Page Application provides security operators with 6 dedicated modules:

1. **Posture Overview**: High-level attack surface score gauge (0-100), deterministic priority distribution (P1-P5), perimeter KPI cards, and recent assessment executions.
2. **Scan & Assess**: Target boundary configuration, interactive scope validation feedback, port preset selectors, background scan dispatch, real-time probe progress telemetry, and cooperative scan cancellation.
3. **Asset Inventory**: Filterable inventory grid with search (IP/hostname) and criticality filters; host slide-out drawer displaying observed listeners, banners, and CPEs.
4. **Vulnerabilities Triage**: Multi-facet filtering by severity, priority tier, and lifecycle state; CISA KEV callout badges; interactive state transitions (`confirmed`, `false_positive`, `accepted_risk`, `needs_review`) with auditable evidence logging.
5. **Assessment Differencer**: Coverage-aware comparison of database runs or uploaded snapshot JSON files; visual risk drift badge ($\Delta \text{Score}$ and direction); executive narrative brief; port state transitions; and software version update detection.
6. **Audit Reports & Snapshots**: One-click streaming downloads for self-contained HTML, JSON, Markdown, and CSV reports; snapshot exports and schema-validated imports.

---

## Defensive Engineering & Security Model

ReconForge is engineered to the highest defensive cybersecurity standards:
- **Zero Exploit Code**: Strictly an assessment and intelligence platform. Contains no exploit payloads, fuzzing engines, brute-force modules, or evasion techniques.
- **SSRF Immunity**: Hardcoded blocks prevent scanning link-local or cloud metadata IP addresses (`169.254.169.254`).
- **XML Security**: All XML parsing utilizes `defusedxml` to mitigate XML External Entity (XXE) and recursive entity expansion attacks.
- **Safe Subprocess Execution**: External binaries (e.g. Nmap) are executed strictly via argument lists without shell interpretation (`shell=False`).
- **Timing-Attack Resistance**: API authentication relies on `secrets.compare_digest` for constant-time validation.
- **Static Security Audits**: 0 Bandit issues across 10,328+ lines of code.

---

## Verification & Testing

ReconForge maintains a rigorous automated test suite covering unit, integration, and security boundaries.

```bash
# Execute complete pytest suite
pytest -v

# Run code formatting checks
ruff format --check .

# Run static linter
ruff check .

# Run security static analysis
bandit -r src/
```

- **Automated Tests**: 168 of 168 passing (100% pass rate).
- **Security Scans**: 0 issues identified by Bandit.
- **Lint & Format**: 100% compliance across 113 source files.

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
