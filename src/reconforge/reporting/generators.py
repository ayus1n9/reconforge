"""Multi-format report generators with formula injection and XSS defenses."""

import csv
import html
import io
import json
from typing import Any

from reconforge.reporting.models import AssessmentReport


def sanitize_csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection (CWE-1236).

    Prepends a single quote (') to any cell starting with dangerous control characters.
    """
    if value is None:
        return ""
    val_str = str(value)
    if not val_str:
        return ""
    # Check for leading formula tokens or control characters
    if val_str[0] in {"=", "+", "-", "@", "\t", "\r"}:
        return f"'{val_str}"
    return val_str


class JSONReportGenerator:
    """Generates structured machine-readable JSON assessment reports."""

    @classmethod
    def generate(cls, report: AssessmentReport) -> str:
        """Serialize assessment report to formatted JSON string."""
        return report.model_dump_json(indent=2)


class MarkdownReportGenerator:
    """Generates GitHub Flavored Markdown assessment reports with executive summaries."""

    @classmethod
    def generate(cls, report: AssessmentReport) -> str:
        """Render complete assessment report in Markdown."""
        lines: list[str] = []

        # Header
        lines.append(f"# {report.metadata.title}")
        lines.append(f"**Classification:** `{report.metadata.classification}`  ")
        lines.append(f"**Assessment ID:** `{report.metadata.assessment_id}`  ")
        lines.append(
            f"**Generated At (UTC):** `{report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`  "
        )
        lines.append(f"**Platform Version:** `ReconForge v{report.metadata.scanner_version}`  ")
        lines.append(f"**Organization:** {report.metadata.organization}\n")
        lines.append("---\n")

        # Executive Risk Posture
        lines.append("## 1. Executive Risk Posture")
        lines.append(
            f"- **Attack-Surface Risk Score:** **{report.risk_posture.overall_score:.1f} / 100.0** (`{report.risk_posture.risk_level}`)"
        )
        lines.append(
            f"- **Assessed Assets:** {report.risk_posture.assessed_assets_count} total ({report.risk_posture.assets_at_risk_count} exposed or at-risk)"
        )
        lines.append(
            f"- **Active Findings:** {len(report.findings)} identified security exposures & vulnerabilities\n"
        )

        # Priority Distribution
        lines.append("### Remediation Urgency Breakdown")
        lines.append("| Priority Tier | Description | Finding Count |")
        lines.append("| :--- | :--- | :---: |")
        p_desc = {
            "P1": "Immediate / Critical (CISA KEV or Critical on Key Asset)",
            "P2": "High Urgency (Critical/High Vuln or Database Exposure)",
            "P3": "Medium Urgency (Cleartext Protocols / Legacy TLS)",
            "P4": "Low Urgency (Minor Misconfiguration / Weak Hygiene)",
            "P5": "Informational (Version Disclosure / Routine Observation)",
        }
        for p_tier in ["P1", "P2", "P3", "P4", "P5"]:
            count = report.risk_posture.priority_distribution.get(p_tier, 0)
            lines.append(f"| **{p_tier}** | {p_desc.get(p_tier, '')} | {count} |")
        lines.append("")

        # Key Drivers
        if report.risk_posture.key_exposure_drivers:
            lines.append("### Primary Attack-Surface Drivers")
            for driver in report.risk_posture.key_exposure_drivers:
                lines.append(f"- ⚠️ {driver}")
            lines.append("")

        lines.append("---\n")

        # Assets Table
        lines.append("## 2. Assessed Asset Inventory")
        if not report.assets:
            lines.append("_No assets recorded in assessment scope._\n")
        else:
            lines.append(
                "| IP Address | Criticality | Risk Score | Risk Tier | Open Ports | Findings |"
            )
            lines.append("| :--- | :---: | :---: | :---: | :--- | :---: |")
            for a in report.assets:
                ports_str = ", ".join(str(p) for p in a.open_ports) if a.open_ports else "None"
                lines.append(
                    f"| `{a.ip_address}` | {a.criticality.upper()} | **{a.risk_score:.1f}** | `{a.risk_level}` | {ports_str} | {a.findings_count} |"
                )
            lines.append("")

        lines.append("---\n")

        # Prioritized Findings Catalog
        lines.append(f"## 3. Prioritized Security Findings ({len(report.findings)})")
        if not report.findings:
            lines.append(
                "✅ _Zero unmitigated security exposures or vulnerabilities identified._\n"
            )
        else:
            # Sort findings by Priority (P1 first)
            sorted_findings = sorted(report.findings, key=lambda f: f.priority)
            for idx, f in enumerate(sorted_findings, 1):
                target_str = f"`{f.target_ip}`"
                if f.port:
                    target_str += f":{f.port}"
                cve_badge = f" (`{f.cve_id}`)" if f.cve_id else ""
                lines.append(f"### {idx}. [{f.priority}] {f.title}{cve_badge}")
                lines.append(
                    f"- **Severity:** `{f.severity.upper()}` | **Rule ID:** `{f.rule_id}` | **Target:** {target_str} | **State:** `{f.state.upper()}`"
                )
                lines.append(f"- **Description:** {f.description}")
                if f.remediation_guidance:
                    lines.append(f"- **Remediation:** {f.remediation_guidance}")
                if f.evidence:
                    lines.append(f"- **Observable Evidence:** `{json.dumps(f.evidence)}`")
                lines.append("")

        lines.append("---\n")

        # Actionable Remediation Roadmap
        lines.append("## 4. Prioritized Remediation Roadmap")
        if not report.remediation_roadmap:
            lines.append("✅ _No outstanding remediation tasks required._\n")
        else:
            lines.append("| Task # | Priority | Target | Action Required |")
            lines.append("| :---: | :---: | :--- | :--- |")
            for idx, task in enumerate(report.remediation_roadmap, 1):
                lines.append(
                    f"| {idx} | **{task.get('priority', 'P3')}** | `{task.get('target', '-')}` | {task.get('action', '-')} |"
                )
            lines.append("")

        return "\n".join(lines)


class CSVReportGenerator:
    """Generates tabular CSV reports fortified against formula injection attacks."""

    @classmethod
    def generate(cls, report: AssessmentReport) -> str:
        """Serialize findings into a safe, formula-neutralized CSV document."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header Row
        writer.writerow(
            [
                "Priority",
                "Severity",
                "Title",
                "Rule ID",
                "CVE ID",
                "Target IP",
                "Port",
                "State",
                "Description",
                "Remediation Guidance",
                "Evidence JSON",
            ]
        )

        sorted_findings = sorted(report.findings, key=lambda f: f.priority)
        for f in sorted_findings:
            writer.writerow(
                [
                    sanitize_csv_cell(f.priority),
                    sanitize_csv_cell(f.severity.upper()),
                    sanitize_csv_cell(f.title),
                    sanitize_csv_cell(f.rule_id),
                    sanitize_csv_cell(f.cve_id or ""),
                    sanitize_csv_cell(f.target_ip),
                    sanitize_csv_cell(str(f.port) if f.port is not None else ""),
                    sanitize_csv_cell(f.state.upper()),
                    sanitize_csv_cell(f.description),
                    sanitize_csv_cell(f.remediation_guidance or ""),
                    sanitize_csv_cell(json.dumps(f.evidence) if f.evidence else ""),
                ]
            )

        return output.getvalue()


class HTMLReportGenerator:
    """Generates standalone, self-contained executive HTML reports with strict XSS escaping."""

    @classmethod
    def generate(cls, report: AssessmentReport) -> str:
        """Render complete HTML report with zero external CDN dependencies."""
        # Safe HTML Escapes
        esc_title = html.escape(report.metadata.title, quote=True)
        esc_class = html.escape(report.metadata.classification, quote=True)
        esc_id = html.escape(report.metadata.assessment_id, quote=True)
        esc_date = html.escape(
            report.metadata.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"), quote=True
        )
        esc_ver = html.escape(report.metadata.scanner_version, quote=True)
        esc_org = html.escape(report.metadata.organization, quote=True)

        score_color = "#10b981"  # Green
        if report.risk_posture.overall_score >= 80.0:
            score_color = "#ef4444"  # Red
        elif report.risk_posture.overall_score >= 60.0:
            score_color = "#f97316"  # Orange
        elif report.risk_posture.overall_score >= 35.0:
            score_color = "#eab308"  # Yellow

        # Priority distribution rows
        priority_rows = []
        p_desc = {
            "P1": "Immediate / Critical (CISA KEV or Critical on Key Asset)",
            "P2": "High Urgency (Critical/High Vuln or Database Exposure)",
            "P3": "Medium Urgency (Cleartext Protocols / Legacy TLS)",
            "P4": "Low Urgency (Minor Misconfiguration / Weak Hygiene)",
            "P5": "Informational (Version Disclosure / Routine Observation)",
        }
        for p in ["P1", "P2", "P3", "P4", "P5"]:
            c = report.risk_posture.priority_distribution.get(p, 0)
            badge_class = f"badge-{p.lower()}"
            priority_rows.append(
                f"<tr><td><span class='badge {badge_class}'>{p}</span></td>"
                f"<td>{html.escape(p_desc.get(p, ''), quote=True)}</td>"
                f"<td style='text-align:center; font-weight:bold;'>{c}</td></tr>"
            )

        # Asset inventory rows
        asset_rows = []
        for a in report.assets:
            ports_str = html.escape(
                ", ".join(str(p) for p in a.open_ports) if a.open_ports else "None", quote=True
            )
            asset_rows.append(
                f"<tr>"
                f"<td><code>{html.escape(a.ip_address, quote=True)}</code></td>"
                f"<td>{html.escape(a.criticality.upper(), quote=True)}</td>"
                f"<td style='font-weight:bold;'>{a.risk_score:.1f}</td>"
                f"<td><span class='risk-{a.risk_level.lower()}'>{html.escape(a.risk_level, quote=True)}</span></td>"
                f"<td>{ports_str}</td>"
                f"<td style='text-align:center;'>{a.findings_count}</td>"
                f"</tr>"
            )

        # Findings cards
        finding_cards = []
        sorted_findings = sorted(report.findings, key=lambda f: f.priority)
        for idx, f in enumerate(sorted_findings, 1):
            target_str = html.escape(f.target_ip + (f":{f.port}" if f.port else ""), quote=True)
            cve_str = (
                f" <span class='cve-badge'>{html.escape(f.cve_id, quote=True)}</span>"
                if f.cve_id
                else ""
            )
            remed_str = (
                f"<div class='remediation-box'><strong>Remediation:</strong> {html.escape(f.remediation_guidance, quote=True)}</div>"
                if f.remediation_guidance
                else ""
            )
            evid_str = (
                f"<details><summary>Observable Evidence</summary><pre>{html.escape(json.dumps(f.evidence, indent=2), quote=True)}</pre></details>"
                if f.evidence
                else ""
            )

            finding_cards.append(
                f"<div class='finding-card priority-border-{f.priority.lower()}'>"
                f"<div class='finding-header'>"
                f"<span class='badge badge-{f.priority.lower()}'>{html.escape(f.priority, quote=True)}</span>"
                f"<span class='badge badge-sev-{f.severity.lower()}'>{html.escape(f.severity.upper(), quote=True)}</span>"
                f"<h3 style='display:inline; margin-left:8px;'>#{idx} {html.escape(f.title, quote=True)}{cve_str}</h3>"
                f"</div>"
                f"<div class='finding-meta'>"
                f"<span><strong>Rule:</strong> {html.escape(f.rule_id, quote=True)}</span> | "
                f"<span><strong>Target:</strong> {target_str}</span> | "
                f"<span><strong>State:</strong> {html.escape(f.state.upper(), quote=True)}</span>"
                f"</div>"
                f"<p class='finding-desc'>{html.escape(f.description, quote=True)}</p>"
                f"{remed_str}"
                f"{evid_str}"
                f"</div>"
            )

        # Build complete HTML5
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc_title}</title>
<style>
  :root {{
    --bg-main: #0f172a;
    --bg-card: #1e293b;
    --text-main: #f8fafc;
    --text-dim: #94a3b8;
    --border: #334155;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  body {{
    font-family: var(--font);
    background-color: var(--bg-main);
    color: var(--text-main);
    margin: 0;
    padding: 24px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{
    border-bottom: 2px solid var(--border);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .classification {{
    display: inline-block;
    background: #e11d48;
    color: white;
    font-size: 11px;
    font-weight: bold;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: 1px;
    margin-bottom: 8px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    font-size: 13px;
    color: var(--text-dim);
  }}
  .posture-panel {{
    display: grid;
    grid-template-columns: 220px 1fr;
    gap: 20px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 24px;
  }}
  .score-dial {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border-right: 1px solid var(--border);
    padding-right: 20px;
  }}
  .score-number {{
    font-size: 54px;
    font-weight: 800;
    color: {score_color};
    line-height: 1;
  }}
  .score-label {{
    font-size: 12px;
    font-weight: bold;
    color: var(--text-dim);
    margin-top: 4px;
    text-transform: uppercase;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
    font-size: 14px;
  }}
  th, td {{
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  th {{ background: #1a2234; color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 12px; }}
  .badge {{
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
  }}
  .badge-p1 {{ background: #dc2626; color: white; }}
  .badge-p2 {{ background: #ea580c; color: white; }}
  .badge-p3 {{ background: #ca8a04; color: white; }}
  .badge-p4 {{ background: #2563eb; color: white; }}
  .badge-p5 {{ background: #475569; color: white; }}
  .badge-sev-critical {{ background: #be123c; color: white; }}
  .badge-sev-high {{ background: #dc2626; color: white; }}
  .badge-sev-medium {{ background: #d97706; color: white; }}
  .badge-sev-low {{ background: #1d4ed8; color: white; }}
  .badge-sev-info {{ background: #475569; color: white; }}
  .risk-critical {{ color: #ef4444; font-weight: bold; }}
  .risk-high {{ color: #f97316; font-weight: bold; }}
  .risk-medium {{ color: #eab308; font-weight: bold; }}
  .risk-low {{ color: #3b82f6; font-weight: bold; }}
  .risk-negligible {{ color: #10b981; font-weight: bold; }}
  .finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 14px;
  }}
  .priority-border-p1 {{ border-left: 5px solid #dc2626; }}
  .priority-border-p2 {{ border-left: 5px solid #ea580c; }}
  .priority-border-p3 {{ border-left: 5px solid #ca8a04; }}
  .priority-border-p4 {{ border-left: 5px solid #2563eb; }}
  .priority-border-p5 {{ border-left: 5px solid #475569; }}
  .finding-meta {{ font-size: 13px; color: var(--text-dim); margin: 6px 0 10px 0; }}
  .remediation-box {{
    background: #0f2027;
    border: 1px solid #1e3a5f;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 13px;
    margin-top: 10px;
    color: #38bdf8;
  }}
  .cve-badge {{ background: #3730a3; color: white; font-size: 11px; padding: 2px 6px; border-radius: 3px; }}
  pre {{ background: #0b0f19; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; }}
  details {{ margin-top: 10px; font-size: 12px; color: var(--text-dim); }}
  @media print {{
    body {{ background: white; color: black; }}
    .posture-panel, .finding-card {{ border: 1px solid #ccc; background: white; color: black; }}
    th {{ background: #eee; color: black; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="classification">{esc_class}</div>
    <h1 style="margin: 4px 0 12px 0;">{esc_title}</h1>
    <div class="meta-grid">
      <div><strong>Assessment ID:</strong> {esc_id}</div>
      <div><strong>Generated:</strong> {esc_date}</div>
      <div><strong>Platform:</strong> ReconForge v{esc_ver}</div>
      <div><strong>Organization:</strong> {esc_org}</div>
    </div>
  </div>

  <h2>Executive Risk Posture</h2>
  <div class="posture-panel">
    <div class="score-dial">
      <div class="score-number">{report.risk_posture.overall_score:.1f}</div>
      <div class="score-label">{html.escape(report.risk_posture.risk_level, quote=True)} RISK</div>
    </div>
    <div>
      <p style="margin-top:0;">
        This assessment evaluated <strong>{report.risk_posture.assessed_assets_count}</strong> network target(s),
        identifying <strong>{report.risk_posture.assets_at_risk_count}</strong> exposed asset(s) and
        <strong>{len(report.findings)}</strong> actionable security finding(s).
      </p>
      <table>
        <thead><tr><th>Priority</th><th>Remediation Urgency</th><th style="text-align:center;">Count</th></tr></thead>
        <tbody>
          {"".join(priority_rows)}
        </tbody>
      </table>
    </div>
  </div>

  <h2>Assessed Network Assets</h2>
  <table>
    <thead><tr><th>IP Address</th><th>Criticality</th><th>Risk Score</th><th>Risk Tier</th><th>Open Ports</th><th style="text-align:center;">Findings</th></tr></thead>
    <tbody>
      {"".join(asset_rows) if asset_rows else "<tr><td colspan='6'>No assets assessed.</td></tr>"}
    </tbody>
  </table>

  <h2>Prioritized Findings & Remediation Playbooks ({len(report.findings)})</h2>
  {"".join(finding_cards) if finding_cards else "<p>✅ Zero security exposures or vulnerabilities identified.</p>"}

</div>
</body>
</html>"""
