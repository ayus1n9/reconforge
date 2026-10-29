"""Command-line interface for ReconForge."""

import asyncio
import json
import logging
import platform
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from reconforge import __version__
from reconforge.assessment.custom_rules import RuleLoadingError, load_rules_from_file
from reconforge.assessment.engine import ExposureEngine
from reconforge.core.enums import ObservationConfidence, PortState, SeverityLevel
from reconforge.core.exceptions import ScopeViolationError
from reconforge.core.models import (
    ScanConfig,
    ScanProgress,
    ScanTarget,
    TargetScope,
)
from reconforge.core.scope import ScopeManager
from reconforge.discovery.dns_resolver import DNSResolver
from reconforge.discovery.tcp_scanner import AsyncTCPScanner
from reconforge.intelligence.builtin_cves import BUILTIN_CVES
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.correlator import VulnerabilityCorrelator
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import SnapshotManager
from reconforge.storage.database import DatabaseManager
from reconforge.utils.logging import setup_logging
from reconforge.utils.network import parse_ports

logger = logging.getLogger("reconforge.cli")

app = typer.Typer(
    name="reconforge",
    help="ReconForge: Intelligent Network Attack-Surface Mapping & Exposure Assessment Platform.",
    add_completion=False,
)
assets_app = typer.Typer(
    name="assets", help="Manage inventoried network assets and exposed services."
)
assessments_app = typer.Typer(
    name="assessments", help="Inspect historical security assessment runs."
)
snapshot_app = typer.Typer(
    name="snapshot", help="Export and import validated assessment snapshots."
)
findings_app = typer.Typer(
    name="findings", help="Inspect and manage identified security exposures and findings."
)
rules_app = typer.Typer(
    name="rules", help="Inspect and validate declarative exposure assessment rules."
)
cve_app = typer.Typer(name="cve", help="Vulnerability intelligence and CVE correlation engine.")

app.add_typer(assets_app)
app.add_typer(assessments_app)
app.add_typer(snapshot_app)
app.add_typer(findings_app)
app.add_typer(rules_app)
app.add_typer(cve_app)

console = Console()


def format_severity(severity: str) -> str:
    """Format finding severity rating with appropriate terminal styling."""
    s = severity.lower()
    if s == "critical":
        return "[bold white on red] CRITICAL [/bold white on red]"
    elif s == "high":
        return "[bold red]HIGH[/bold red]"
    elif s == "medium":
        return "[bold yellow]MEDIUM[/bold yellow]"
    elif s == "low":
        return "[bold blue]LOW[/bold blue]"
    return "[cyan]INFO[/cyan]"


def format_match_level(match_level: str) -> str:
    """Format calibrated CVE match level with distinct terminal styling."""
    m = match_level.lower()
    if m == "strong_candidate":
        return "[bold green]STRONG CANDIDATE[/bold green]"
    elif m == "manual_verification_required":
        return "[bold yellow]MANUAL VERIFICATION REQUIRED[/bold yellow]"
    elif m == "possible_match":
        return "[magenta]POSSIBLE MATCH[/magenta]"
    return "[dim]INSUFFICIENT EVIDENCE[/dim]"


@app.command()
def version() -> None:
    """Display ReconForge version, architecture, and environment information."""
    console.print(
        Panel.fit(
            f"[bold cyan]ReconForge[/bold cyan] [green]v{__version__}[/green]\n"
            f"[dim]Platform:[/dim] {platform.system()} {platform.machine()} (Python {platform.python_version()})\n"
            f"[dim]License:[/dim] Apache-2.0\n"
            f"[dim]Mode:[/dim] Authorized Security Assessment Only",
            title="System Information",
            border_style="cyan",
        )
    )


@app.command()
def scan(
    targets: Annotated[
        str,
        typer.Argument(
            help="Target IP, CIDR, or comma-separated list (e.g. '127.0.0.1' or '10.0.0.0/24')."
        ),
    ],
    ports: Annotated[
        str, typer.Option("--ports", "-p", help="Port specification (e.g. '80,443', '1-1024').")
    ] = "21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443",
    concurrency: Annotated[
        int, typer.Option("--concurrency", "-c", help="Maximum concurrent probe tasks.")
    ] = 50,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", help="Socket connection timeout in seconds.")
    ] = 2.0,
    rate_limit: Annotated[
        int,
        typer.Option("--rate", "-r", help="Maximum probes per second (0 = unthrottled)."),
    ] = 100,
    allow_public: Annotated[
        bool,
        typer.Option(
            "--allow-public",
            help="Authorize scanning of public Internet addresses (disabled by default).",
        ),
    ] = False,
    host_discovery: Annotated[
        bool,
        typer.Option("--host-discovery", help="Perform pre-scan TCP host liveness discovery."),
    ] = False,
    fingerprint: Annotated[
        bool,
        typer.Option(
            "--fingerprint/--no-fingerprint",
            "-F",
            help="Attempt protocol service fingerprinting on open ports.",
        ),
    ] = True,
    use_nmap: Annotated[
        bool,
        typer.Option("--use-nmap", help="Use optional local Nmap service scan integration."),
    ] = False,
    save: Annotated[
        bool,
        typer.Option(
            "--save/--no-save",
            help="Persist assessment, assets, and services into inventory database.",
        ),
    ] = True,
    assess: Annotated[
        bool,
        typer.Option(
            "--assess/--no-assess",
            help="Evaluate declarative exposure rules on discovered services.",
        ),
    ] = True,
    correlate_cves: Annotated[
        bool,
        typer.Option(
            "--correlate-cves",
            help="Correlate identified services against vulnerability intelligence and record CVE findings.",
        ),
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Confirm execution without interactive prompt.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Format output as JSON instead of rich tables.")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose debug logging.")
    ] = False,
) -> None:
    """Execute an authorized asynchronous TCP discovery assessment.

    Strict scope allowlisting, DNS pinning, bounded concurrency, and service fingerprinting are enforced.
    """
    setup_logging(level="DEBUG" if verbose else "INFO")

    target_list = [t.strip() for t in targets.split(",") if t.strip()]
    if not target_list:
        console.print("[bold red]Error:[/bold red] No targets provided.")
        raise typer.Exit(code=1)

    # 1. Scope Setup & Validation
    try:
        parsed_ports = parse_ports(ports)
    except Exception as err:
        console.print(f"[bold red]Port Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err

    scope = TargetScope(
        allowed_targets=target_list,
        allowed_ports=ports,
        allow_public_targets=allow_public,
        lab_mode=True,
    )

    try:
        scope_manager = ScopeManager(scope)
    except Exception as err:
        console.print(f"[bold red]Scope Configuration Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err

    # 2. Hostname resolution & target expansion
    try:
        scan_targets: list[ScanTarget] = scope_manager.expand_static_targets()
        if scope_manager.allowed_hostnames:
            resolver = DNSResolver(scope_manager=scope_manager, timeout_seconds=timeout)
            resolved = asyncio.run(resolver.resolve_all_scoped_hostnames())
            scan_targets.extend(resolved)
    except ScopeViolationError as err:
        console.print(f"[bold red]Scope Violation:[/bold red] {err}")
        raise typer.Exit(code=2) from err
    except Exception as err:
        console.print(f"[bold red]Target Preparation Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err

    if not scan_targets:
        console.print(
            "[bold yellow]Warning:[/bold yellow] No valid targets within authorized scope."
        )
        raise typer.Exit(code=1)

    # 3. Explicit Authorization Confirmation Prompt (Safety boundary)
    if not yes:
        total_probes = len(scan_targets) * len(parsed_ports)
        console.print(
            Panel(
                f"[bold yellow]ReconForge Assessment Scope Confirmation[/bold yellow]\n\n"
                f"• [bold]Targets:[/bold] {len(scan_targets)} resolved destinations ({', '.join(t.ip for t in scan_targets[:5])}{'...' if len(scan_targets) > 5 else ''})\n"
                f"• [bold]Ports:[/bold] {len(parsed_ports)} ({ports})\n"
                f"• [bold]Total Probes:[/bold] {total_probes}\n"
                f"• [bold]Fingerprinting:[/bold] {fingerprint} (Nmap: {use_nmap})\n"
                f"• [bold]Concurrency:[/bold] {concurrency} (Rate Limit: {rate_limit}/sec)\n"
                f"• [bold]Public Internet Allowed:[/bold] {allow_public}\n\n"
                f"[red]NOTICE: Ensure you have explicit written authorization for all target networks.[/red]",
                border_style="yellow",
            )
        )
        confirmed = typer.confirm("Do you wish to proceed with this authorized assessment?")
        if not confirmed:
            console.print("[yellow]Scan aborted by user.[/yellow]")
            raise typer.Exit(code=0)

    config = ScanConfig(
        timeout_seconds=timeout,
        concurrency=concurrency,
        rate_limit_per_second=rate_limit,
        skip_host_discovery=not host_discovery,
        fingerprint_services=fingerprint,
        use_nmap=use_nmap,
    )

    # 4. Asynchronous Scan Execution
    scanner = AsyncTCPScanner(scope_manager=scope_manager, config=config)

    async def run_scan():
        return await scanner.scan_targets(scan_targets, parsed_ports)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        disable=json_output,
    ) as progress_ui:
        task_id = progress_ui.add_task(
            "[cyan]Scanning & identifying target ports...",
            total=len(scan_targets) * len(parsed_ports),
        )

        def update_progress(p: ScanProgress):
            progress_ui.update(task_id, completed=p.completed_probes)

        scanner.progress_callback = update_progress
        try:
            observations, summary = asyncio.run(run_scan())
        except KeyboardInterrupt as err:
            console.print("\n[bold red]Interrupted! Aborting scan...[/bold red]")
            scanner.cancel()
            raise typer.Exit(code=130) from err

    # 5. Persistent Inventory Recording & Exposure Assessment (Phase 3 & 4)
    findings = []
    if save and summary.status != "cancelled":
        try:
            db_mgr = DatabaseManager()
            repo = AssetRepository(db_mgr)
            repo.record_scan_results(
                assessment_id=summary.scan_id,
                scope_config=scope.model_dump(),
                scanner_version=__version__,
                observations=observations,
                summary=summary,
            )
            if assess:
                engine = ExposureEngine()
                findings = engine.evaluate_assessment(summary.scan_id, db_mgr, persist=True)
            if correlate_cves:
                correlator = VulnerabilityCorrelator(cache=VulnerabilityCache(db_mgr))
                correlator.correlate_assessment_services(
                    summary.scan_id, repo, record_findings=True, online=False
                )
                findings = repo.list_findings(assessment_id=summary.scan_id)
        except Exception as save_err:
            logger.warning("Failed to persist scan results or assess exposures: %s", save_err)

    # 6. Output Presentation
    if json_output:
        findings_json = []
        for f in findings:
            if hasattr(f, "model_dump"):
                findings_json.append(f.model_dump(mode="json"))
            else:
                findings_json.append(
                    {
                        "id": f.id,
                        "rule_id": f.rule_id,
                        "cve_id": f.cve_id,
                        "title": f.title,
                        "severity": f.severity,
                        "state": f.state,
                        "evidence": f.evidence,
                    }
                )
        out = {
            "summary": summary.model_dump(),
            "observations": [obs.model_dump(mode="json") for obs in observations],
            "findings": findings_json,
        }
        console.print(json.dumps(out, indent=2))
        return

    # Rich Table Presentation
    table = Table(
        title=f"ReconForge TCP Assessment Results (Scan ID: {summary.scan_id[:8]})",
        border_style="dim",
    )
    table.add_column("Target IP", style="bold")
    table.add_column("Port", justify="right")
    table.add_column("State", justify="center")
    table.add_column("Service", style="cyan")
    table.add_column("Product", style="green")
    table.add_column("Version", style="bold yellow")
    table.add_column("Confidence", justify="center")
    table.add_column("Latency (ms)", justify="right")

    open_obs = [obs for obs in observations if obs.state == PortState.OPEN]
    other_obs = [obs for obs in observations if obs.state != PortState.OPEN]

    for obs in open_obs:
        srv = obs.service
        service_str = srv.service_name if srv else "unknown"
        product_str = srv.product or "-" if srv else "-"
        version_str = srv.version or "-" if srv else "-"
        conf_str = "-"
        if srv:
            color = {
                ObservationConfidence.HIGH: "green",
                ObservationConfidence.MEDIUM: "yellow",
                ObservationConfidence.LOW: "magenta",
                ObservationConfidence.UNKNOWN: "dim",
            }.get(srv.confidence, "white")
            conf_str = f"[{color}]{srv.confidence.value.upper()}[/{color}]"

        table.add_row(
            obs.target_ip,
            str(obs.port),
            "[bold green]OPEN[/bold green]",
            service_str,
            product_str,
            version_str,
            conf_str,
            f"{obs.response_time_ms:.1f}" if obs.response_time_ms else "-",
        )

    if verbose:
        for obs in other_obs:
            state_color = {
                PortState.CLOSED: "red",
                PortState.TIMEOUT: "yellow",
                PortState.FILTERED: "magenta",
                PortState.UNREACHABLE: "dim red",
                PortState.ERROR: "bold red",
                PortState.NOT_SCANNED: "dim",
            }.get(obs.state, "white")
            table.add_row(
                obs.target_ip,
                str(obs.port),
                f"[{state_color}]{obs.state.value.upper()}[/{state_color}]",
                "-",
                "-",
                "-",
                "-",
                f"{obs.response_time_ms:.1f}" if obs.response_time_ms else "-",
            )

    console.print(table)

    summary_panel = Panel(
        f"[bold]Targets Assessed:[/bold] {summary.targets_assessed}  |  "
        f"[bold]Probes Attempted:[/bold] {summary.probes_attempted}  |  "
        f"[bold green]Open:[/bold green] {summary.open_count}  |  "
        f"[bold red]Closed:[/bold red] {summary.closed_count}  |  "
        f"[bold yellow]Timeout:[/bold yellow] {summary.timeout_count}  |  "
        f"[bold magenta]Filtered:[/bold magenta] {summary.filtered_count}  |  "
        f"[bold]Duration:[/bold] {summary.duration_seconds}s",
        title="Assessment Summary",
        border_style="green" if summary.status == "completed" else "yellow",
    )
    console.print(summary_panel)

    if findings:
        f_table = Table(
            title=f"Identified Exposures & Findings ({len(findings)})",
            border_style="bold red",
        )
        f_table.add_column("Severity", justify="center")
        f_table.add_column("Rule ID", style="bold")
        f_table.add_column("Title")
        f_table.add_column("Target")
        f_table.add_column("State")

        for f in findings:
            target = f.evidence.get("ip_address") or "-"
            if f.evidence.get("port"):
                target += f":{f.evidence['port']}"
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            state_str = f.state.value if hasattr(f.state, "value") else str(f.state)
            f_table.add_row(
                format_severity(sev_str),
                f.rule_id,
                f.title,
                target,
                state_str.upper(),
            )
        console.print(f_table)
        console.print(
            "[dim]Run 'reconforge findings list' or 'reconforge findings show <id>' for full details and remediation.[/dim]"
        )


@assets_app.command("list")
def list_assets_cmd(
    limit: Annotated[int, typer.Option("--limit", "-l", help="Maximum assets to return.")] = 50,
) -> None:
    """List all inventoried network assets and their exposed services."""
    db_mgr = DatabaseManager()
    repo = AssetRepository(db_mgr)
    assets = repo.list_assets(limit=limit)

    if not assets:
        console.print(
            "[dim]No assets recorded in inventory yet. Run 'reconforge scan' to populate.[/dim]"
        )
        return

    table = Table(title="ReconForge Asset Inventory", border_style="cyan")
    table.add_column("Asset ID", style="dim")
    table.add_column("IP Address", style="bold")
    table.add_column("Hostnames", style="dim")
    table.add_column("Exposed Services", style="cyan")
    table.add_column("Criticality", justify="center")
    table.add_column("Last Seen", style="italic")

    for asset in assets:
        services_summary = []
        for s in asset.services:
            srv_desc = f"{s.port}/{s.protocol} ({s.service_name})"
            if s.product:
                srv_desc += f": {s.product}"
            services_summary.append(srv_desc)

        services_str = ", ".join(services_summary) if services_summary else "[dim]None open[/dim]"
        hostnames_str = ", ".join(asset.observed_hostnames) if asset.observed_hostnames else "-"
        last_seen = asset.last_observed_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        table.add_row(
            asset.id[:8],
            asset.ip_address,
            hostnames_str,
            services_str,
            asset.criticality.upper(),
            last_seen,
        )

    console.print(table)


@assets_app.command("show")
def show_asset_cmd(
    asset_id_or_ip: Annotated[
        str, typer.Argument(help="UUID or IP address of the asset to inspect.")
    ],
) -> None:
    """Display comprehensive details and service inventory for a specific asset."""
    db_mgr = DatabaseManager()
    repo = AssetRepository(db_mgr)
    asset = repo.get_asset(asset_id_or_ip)

    if not asset:
        console.print(f"[bold red]Asset '{asset_id_or_ip}' not found in inventory.[/bold red]")
        raise typer.Exit(code=1)

    panel_text = (
        f"[bold]Asset ID:[/bold] {asset.id}\n"
        f"[bold]IP Address:[/bold] {asset.ip_address} ({asset.address_family})\n"
        f"[bold]Hostnames:[/bold] {', '.join(asset.observed_hostnames) if asset.observed_hostnames else 'None'}\n"
        f"[bold]Type:[/bold] {asset.asset_type}  |  [bold]Criticality:[/bold] {asset.criticality.upper()}\n"
        f"[bold]First Observed:[/bold] {asset.first_observed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"[bold]Last Observed:[/bold] {asset.last_observed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"[bold]Discovery Sources:[/bold] {', '.join(asset.discovery_sources or [])}"
    )
    console.print(
        Panel(panel_text, title=f"Asset Profile: {asset.ip_address}", border_style="cyan")
    )

    table = Table(title=f"Discovered Services ({len(asset.services)})", border_style="dim")
    table.add_column("Port", justify="right")
    table.add_column("Proto", justify="center")
    table.add_column("Service", style="cyan")
    table.add_column("Product", style="green")
    table.add_column("Version", style="bold yellow")
    table.add_column("Confidence", justify="center")
    table.add_column("Banner / Extra Info")

    for s in asset.services:
        banner = s.banner_snippet or "-"
        if s.tls_metadata:
            proto = s.tls_metadata.get("protocol_version") or "TLS"
            cipher = s.tls_metadata.get("cipher_suite") or ""
            banner = f"TLS: {proto} ({cipher}) | {banner}"
        table.add_row(
            str(s.port),
            s.protocol.upper(),
            s.service_name,
            s.product or "-",
            s.version or "-",
            s.confidence.upper(),
            banner,
        )

    console.print(table)


@assessments_app.command("list")
def list_assessments_cmd(
    limit: Annotated[
        int, typer.Option("--limit", "-l", help="Maximum assessments to return.")
    ] = 50,
) -> None:
    """List historical assessment runs and execution statistics."""
    db_mgr = DatabaseManager()
    repo = AssetRepository(db_mgr)
    assessments = repo.list_assessments(limit=limit)

    if not assessments:
        console.print("[dim]No assessments recorded yet.[/dim]")
        return

    table = Table(title="Assessment History", border_style="green")
    table.add_column("Assessment ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Targets", justify="right")
    table.add_column("Probes", justify="right")
    table.add_column("Open Ports", justify="right")
    table.add_column("Started At", style="italic")

    for a in assessments:
        cov = a.coverage_metrics or {}
        targets_num = str(cov.get("targets_assessed", "-"))
        probes_num = str(cov.get("probes_attempted", "-"))
        open_num = str(cov.get("open_count", "-"))
        start_str = a.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        status_color = "green" if a.status == "completed" else "yellow"
        table.add_row(
            a.id[:8],
            a.name,
            f"[{status_color}]{a.status.upper()}[/{status_color}]",
            targets_num,
            probes_num,
            open_num,
            start_str,
        )

    console.print(table)


@snapshot_app.command("export")
def export_snapshot_cmd(
    assessment_id: Annotated[str, typer.Argument(help="UUID of the assessment to export.")],
    output: Annotated[
        str | None, typer.Option("--output", "-o", help="File path to save snapshot JSON.")
    ] = None,
) -> None:
    """Export an assessment snapshot to a versioned JSON file."""
    db_mgr = DatabaseManager()
    manager = SnapshotManager(db_mgr)
    try:
        data = manager.export_snapshot(assessment_id)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(data)
            console.print(f"[bold green]Snapshot successfully exported to {output}[/bold green]")
        else:
            console.print(data)
    except Exception as err:
        console.print(f"[bold red]Export Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err


@snapshot_app.command("import")
def import_snapshot_cmd(
    file_path: Annotated[str, typer.Argument(help="Path to snapshot JSON file to import.")],
) -> None:
    """Import and validate an untrusted assessment snapshot JSON file into the database."""
    db_mgr = DatabaseManager()
    manager = SnapshotManager(db_mgr)
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
        assessment = manager.import_snapshot(content)
        console.print(
            f"[bold green]Snapshot successfully imported! Assessment ID: {assessment.id} ({assessment.name})[/bold green]"
        )
    except Exception as err:
        console.print(f"[bold red]Snapshot Import Failed:[/bold red] {err}")
        raise typer.Exit(code=1) from err


@app.command()
def assess(
    assessment_id: Annotated[
        str, typer.Argument(help="UUID or prefix of historical assessment to evaluate.")
    ],
    rules_dir: Annotated[
        str | None, typer.Option("--rules-dir", "-r", help="Path to custom YAML rules directory.")
    ] = None,
) -> None:
    """Evaluate declarative exposure rules against an assessment's inventoried services."""
    db_mgr = DatabaseManager()
    engine = ExposureEngine()
    if rules_dir:
        _, errors = engine.load_custom_directory(rules_dir)
        if errors:
            for err in errors:
                console.print(f"[bold yellow]Warning:[/bold yellow] {err}")

    findings = engine.evaluate_assessment(assessment_id, db_mgr, persist=True)
    if not findings:
        console.print(
            f"[bold green]No exposures identified for assessment '{assessment_id}'.[/bold green]"
        )
        return

    table = Table(
        title=f"Assessment Findings: {assessment_id[:8]} ({len(findings)})",
        border_style="bold red",
    )
    table.add_column("Finding ID", style="dim")
    table.add_column("Severity", justify="center")
    table.add_column("Rule ID", style="bold")
    table.add_column("Title")
    table.add_column("Target")
    table.add_column("State")

    for f in findings:
        target = f.evidence.get("ip_address") or "-"
        if f.evidence.get("port"):
            target += f":{f.evidence['port']}"
        table.add_row(
            f.id[:8],
            format_severity(f.severity.value),
            f.rule_id,
            f.title,
            target,
            f.state.value.upper(),
        )
    console.print(table)
    console.print(
        "[dim]Run 'reconforge findings show <finding_id>' to view complete evidence and remediation playbook.[/dim]"
    )


@findings_app.command("list")
def list_findings_cmd(
    assessment_id: Annotated[
        str | None, typer.Option("--assessment-id", "-a", help="Filter by assessment UUID.")
    ] = None,
    asset_id: Annotated[
        str | None, typer.Option("--asset-id", help="Filter by asset UUID or IP address.")
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity", "-s", help="Filter by severity (critical, high, medium, low, info)."
        ),
    ] = None,
    state: Annotated[
        str | None,
        typer.Option(
            "--state", help="Filter by state (potential_exposure, confirmed, false_positive, etc.)."
        ),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-l", help="Maximum findings to return.")] = 100,
) -> None:
    """List security findings and exposures with severity badges and target locations."""
    db_mgr = DatabaseManager()
    repo = AssetRepository(db_mgr)
    findings = repo.list_findings(
        assessment_id=assessment_id,
        asset_id=asset_id,
        severity=severity,
        state=state,
        limit=limit,
    )

    if not findings:
        console.print("[dim]No security findings match the specified criteria.[/dim]")
        return

    table = Table(title=f"ReconForge Security Findings ({len(findings)})", border_style="bold red")
    table.add_column("Finding ID", style="dim")
    table.add_column("Severity", justify="center")
    table.add_column("Rule ID", style="bold")
    table.add_column("Title")
    table.add_column("Target IP")
    table.add_column("Port/Svc")
    table.add_column("State")

    for f in findings:
        target_ip = f.asset.ip_address if f.asset else "-"
        port_svc = f"{f.service.port}/{f.service.protocol}" if f.service else "-"
        table.add_row(
            f.id[:8],
            format_severity(f.severity),
            f.rule_id,
            f.title,
            target_ip,
            port_svc,
            f.state.upper(),
        )
    console.print(table)
    console.print(
        "[dim]Use 'reconforge findings show <finding_id>' to inspect finding details.[/dim]"
    )


@findings_app.command("show")
def show_finding_cmd(
    finding_id: Annotated[str, typer.Argument(help="UUID or prefix of the finding to inspect.")],
) -> None:
    """Inspect comprehensive technical details, evidence, and remediation for a finding."""
    db_mgr = DatabaseManager()
    repo = AssetRepository(db_mgr)
    finding = repo.get_finding(finding_id)

    if not finding:
        console.print(f"[bold red]Finding '{finding_id}' not found.[/bold red]")
        raise typer.Exit(code=1)

    target_info = f"{finding.asset.ip_address}" if finding.asset else "Unknown"
    if finding.service:
        target_info += f" (Port {finding.service.port}/{finding.service.protocol}"
        if finding.service.service_name != "unknown":
            target_info += f" - {finding.service.service_name}"
        target_info += ")"

    evidence_json = json.dumps(finding.evidence, indent=2)

    panel_text = (
        f"[bold]Finding ID:[/bold] {finding.id}\n"
        f"[bold]Rule ID:[/bold] {finding.rule_id}\n"
        f"[bold]Severity:[/bold] {format_severity(finding.severity)}    "
        f"[bold]State:[/bold] [{finding.state.upper()}]\n"
        f"[bold]Target Asset:[/bold] {target_info}\n"
        f"[bold]Assessment Run:[/bold] {finding.assessment_id}\n"
        f"[bold]First Identified:[/bold] {finding.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"[bold underline]Description:[/bold underline]\n{finding.description}\n\n"
        f"[bold underline]Evidence:[/bold underline]\n[dim]{evidence_json}[/dim]\n\n"
        f"[bold underline]Actionable Remediation Guidance:[/bold underline]\n"
        f"[green]{finding.remediation_guidance or 'No remediation playbook attached.'}[/green]"
    )
    console.print(Panel(panel_text, title=f"Security Finding: {finding.title}", border_style="red"))


@findings_app.command("update")
def update_finding_cmd(
    finding_id: Annotated[str, typer.Argument(help="UUID or prefix of the finding to update.")],
    state: Annotated[
        str,
        typer.Argument(
            help="New finding state (e.g. 'confirmed', 'false_positive', 'accepted_risk', 'needs_review')."
        ),
    ],
) -> None:
    """Update lifecycle state of an exposure finding."""
    db_mgr = DatabaseManager()
    repo = AssetRepository(db_mgr)
    updated = repo.update_finding_state(finding_id, state)
    if not updated:
        console.print(f"[bold red]Finding '{finding_id}' not found.[/bold red]")
        raise typer.Exit(code=1)
    console.print(
        f"[bold green]Updated finding {updated.id[:8]} state to '{updated.state.upper()}'.[/bold green]"
    )


@rules_app.command("list")
def list_rules_cmd(
    category: Annotated[
        str | None, typer.Option("--category", "-c", help="Filter rules by category.")
    ] = None,
    severity: Annotated[
        str | None, typer.Option("--severity", "-s", help="Filter rules by severity.")
    ] = None,
) -> None:
    """List all registered exposure detection rules."""
    engine = ExposureEngine()
    rules = engine.list_rules(category=category, severity=severity)

    table = Table(title=f"Registered Exposure Rules ({len(rules)})", border_style="cyan")
    table.add_column("Rule ID", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("Category")
    table.add_column("Rule Name")
    table.add_column("Ports / Trigger Criteria")

    for r in rules:
        ports_str = ", ".join(str(p) for p in r.conditions.ports) if r.conditions.ports else "any"
        if r.conditions.service_names:
            ports_str += f" ({', '.join(r.conditions.service_names)})"
        table.add_row(
            r.id,
            format_severity(r.severity.value),
            r.category.value,
            r.name,
            ports_str,
        )
    console.print(table)


@rules_app.command("validate")
def validate_rules_cmd(
    rule_path: Annotated[str, typer.Argument(help="Path to YAML rule file to validate.")],
) -> None:
    """Validate a custom YAML rule file against the ExposureRuleDefinition schema."""
    try:
        rules = load_rules_from_file(rule_path)
        console.print(
            f"[bold green]Rule file '{rule_path}' is valid! Loaded {len(rules)} rule(s):[/bold green]"
        )
        for r in rules:
            console.print(
                f" • [bold cyan]{r.id}[/bold cyan]: {r.name} ({format_severity(r.severity.value)})"
            )
    except RuleLoadingError as err:
        console.print(f"[bold red]Rule Validation Error:[/bold red] {err}")
        raise typer.Exit(code=1) from err
    except Exception as err:
        console.print(f"[bold red]Validation Failed:[/bold red] {err}")
        raise typer.Exit(code=1) from err


@cve_app.command("search")
def cve_search_cmd(
    query: Annotated[str | None, typer.Argument(help="Free-text search keyword or CVE ID.")] = None,
    product: Annotated[
        str | None,
        typer.Option(
            "--product", "-p", help="Filter by software product name (e.g. openssh, apache)."
        ),
    ] = None,
    min_cvss: Annotated[
        float | None, typer.Option("--min-cvss", help="Minimum CVSS v3 base score.")
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(
            "--severity", "-s", help="Filter by severity level (critical, high, medium, low)."
        ),
    ] = None,
    known_exploited: Annotated[
        bool,
        typer.Option(
            "--known-exploited",
            help="Filter for CVEs in CISA Known Exploited Vulnerabilities catalog.",
        ),
    ] = False,
    limit: Annotated[int, typer.Option("--limit", "-l", help="Maximum records to return.")] = 25,
    db_path: Annotated[
        str | None, typer.Option("--db-path", help="Path to SQLite database file.")
    ] = None,
) -> None:
    """Search cached vulnerability intelligence by keyword, product, or CVSS score."""
    db_url = f"sqlite:///{db_path}" if db_path else None
    cache = VulnerabilityCache(DatabaseManager(db_url) if db_url else None)

    sev_enum = None
    if severity:
        try:
            sev_enum = SeverityLevel(severity.lower())
        except ValueError:
            console.print(f"[bold red]Invalid severity level:[/bold red] '{severity}'")
            raise typer.Exit(code=1) from None

    items = cache.search_cves(
        query=query,
        cpe_product=product,
        min_cvss=min_cvss,
        severity=sev_enum,
        is_known_exploited=True if known_exploited else None,
    )

    if not items:
        console.print("[dim]No vulnerability intelligence records matched query.[/dim]")
        return

    table = Table(title=f"Vulnerability Intelligence Results ({len(items)})", border_style="cyan")
    table.add_column("CVE ID", style="bold red")
    table.add_column("Severity", justify="center")
    table.add_column("CVSS v3", justify="right")
    table.add_column("KEV", justify="center")
    table.add_column("Product / CPE")
    table.add_column("Description")

    for item in items[:limit]:
        kev_str = "[bold red]YES[/bold red]" if item.is_known_exploited else "[dim]NO[/dim]"
        cpes_str = ", ".join(item.affected_cpes[:2]) if item.affected_cpes else "-"
        table.add_row(
            item.cve_id,
            format_severity(item.severity.value),
            f"{item.cvss_v3_score:.1f}" if item.cvss_v3_score is not None else "-",
            kev_str,
            cpes_str,
            item.description[:75] + "..." if len(item.description) > 75 else item.description,
        )

    console.print(table)
    console.print(
        "[dim]Use 'reconforge cve show <cve-id>' to view comprehensive vulnerability metrics.[/dim]"
    )


@cve_app.command("show")
def cve_show_cmd(
    cve_id: Annotated[str, typer.Argument(help="CVE identifier to inspect (e.g. CVE-2024-6387).")],
    db_path: Annotated[
        str | None, typer.Option("--db-path", help="Path to SQLite database file.")
    ] = None,
) -> None:
    """Display comprehensive technical details, CVSS vectors, and criteria for a CVE."""
    db_url = f"sqlite:///{db_path}" if db_path else None
    cache = VulnerabilityCache(DatabaseManager(db_url) if db_url else None)

    item = cache.get_cve(cve_id)
    if not item:
        console.print(f"[bold red]CVE not found in local cache:[/bold red] '{cve_id}'")
        raise typer.Exit(code=1)

    kev_badge = (
        " [bold red][CISA KEV KNOWN EXPLOITED][/bold red]" if item.is_known_exploited else ""
    )
    panel_content = (
        f"[bold]CVE ID:[/bold] {item.cve_id}{kev_badge}\n"
        f"[bold]Severity:[/bold] {format_severity(item.severity.value)}    "
        f"[bold]CVSS v3 Score:[/bold] {item.cvss_v3_score or '-'}    "
        f"[bold]Vector:[/bold] {item.cvss_v3_vector or '-'}\n"
        f"[bold]CWE IDs:[/bold] {', '.join(item.cwe_ids) if item.cwe_ids else '-'}\n\n"
        f"[bold]Description:[/bold]\n{item.description}\n\n"
        f"[bold]Affected CPEs:[/bold]\n"
        + "\n".join(f" • {cpe}" for cpe in item.affected_cpes)
        + "\n\n"
        + (
            "[bold]Version Criteria Rules:[/bold]\n"
            + "\n".join(f" • {crit}" for crit in item.version_criteria)
            + "\n\n"
            if item.version_criteria
            else ""
        )
        + (
            "[bold]Advisory References:[/bold]\n"
            + "\n".join(f" • {ref}" for ref in item.references)
            if item.references
            else ""
        )
    )
    console.print(
        Panel(
            panel_content,
            title=f"Vulnerability Intelligence: {item.cve_id}",
            border_style="bold red" if item.severity == SeverityLevel.CRITICAL else "yellow",
        )
    )


@cve_app.command("list-builtin")
def cve_list_builtin_cmd() -> None:
    """List all curated built-in offline CVE intelligence entries."""
    table = Table(
        title=f"Curated Offline CVE Intelligence Dataset ({len(BUILTIN_CVES)})",
        border_style="cyan",
    )
    table.add_column("CVE ID", style="bold red")
    table.add_column("Severity", justify="center")
    table.add_column("CVSS v3", justify="right")
    table.add_column("KEV", justify="center")
    table.add_column("Affected Product")
    table.add_column("Summary")

    for item in BUILTIN_CVES:
        kev_str = "[bold red]YES[/bold red]" if item.is_known_exploited else "[dim]NO[/dim]"
        cpes = ", ".join(item.affected_cpes)
        table.add_row(
            item.cve_id,
            format_severity(item.severity.value),
            f"{item.cvss_v3_score:.1f}" if item.cvss_v3_score is not None else "-",
            kev_str,
            cpes,
            item.description[:70] + "..." if len(item.description) > 70 else item.description,
        )

    console.print(table)


@cve_app.command("correlate")
def cve_correlate_cmd(
    assessment_id: Annotated[
        str | None,
        typer.Option(
            "--assessment-id", "-a", help="Correlate services from a specific assessment ID."
        ),
    ] = None,
    record: Annotated[
        bool,
        typer.Option(
            "--record/--no-record", help="Persist correlation results as database findings."
        ),
    ] = True,
    online: Annotated[
        bool,
        typer.Option(
            "--online/--offline", help="Query online NIST NVD API in addition to local cache."
        ),
    ] = False,
    db_path: Annotated[
        str | None, typer.Option("--db-path", help="Path to SQLite database file.")
    ] = None,
) -> None:
    """Correlate inventoried services with vulnerability intelligence and classify confidence tiers."""
    db_url = f"sqlite:///{db_path}" if db_path else None
    db_mgr = DatabaseManager(db_url) if db_url else DatabaseManager()
    repo = AssetRepository(db_mgr)
    cache = VulnerabilityCache(db_mgr)
    correlator = VulnerabilityCorrelator(cache=cache)

    target_assessment_id = assessment_id
    if not target_assessment_id:
        assessments = repo.list_assessments(limit=1)
        if not assessments:
            console.print(
                "[dim]No assessments recorded in inventory yet. Run 'reconforge scan' first.[/dim]"
            )
            return
        target_assessment_id = assessments[0].id

    console.print(
        f"[bold cyan]Correlating services for assessment [bold white]{target_assessment_id[:8]}[/bold white]...[/bold cyan]"
    )
    correlation_map = correlator.correlate_assessment_services(
        assessment_id=target_assessment_id,
        repository=repo,
        record_findings=record,
        online=online,
    )

    total_matches = sum(len(res_list) for res_list in correlation_map.values())
    if total_matches == 0:
        console.print(
            "[bold green]Zero CVE correlations matched for discovered services.[/bold green]"
        )
        return

    table = Table(
        title=f"Calibrated CVE Correlation Results ({total_matches} candidate matches)",
        border_style="bold red",
    )
    table.add_column("Service ID", style="dim")
    table.add_column("CVE ID", style="bold red")
    table.add_column("Severity", justify="center")
    table.add_column("Match Level")
    table.add_column("Matched Version", style="yellow")
    table.add_column("Evidence Rationale")

    for s_id, res_list in correlation_map.items():
        for res in res_list:
            table.add_row(
                s_id[:8],
                res.cve.cve_id,
                format_severity(res.cve.severity.value),
                format_match_level(res.match_level.value),
                res.matched_version or "-",
                res.evidence_rationale[:80] + "..."
                if len(res.evidence_rationale) > 80
                else res.evidence_rationale,
            )

    console.print(table)
    if record:
        console.print(
            f"[bold green]Successfully recorded {total_matches} vulnerability findings to database.[/bold green]"
        )
        console.print(
            "[dim]Run 'reconforge findings list' to inspect findings lifecycle states.[/dim]"
        )


@app.command()
def validate_scope(
    config_path: Annotated[str, typer.Argument(help="Path to YAML or JSON scope definition file.")],
) -> None:
    """Validate a scope configuration file and display parsed authorization boundaries."""
    try:
        with open(config_path, encoding="utf-8") as f:
            if config_path.endswith((".yaml", ".yml")):
                raw = yaml.safe_load(f)
            else:
                raw = json.load(f)
        scope = TargetScope(**raw)
        manager = ScopeManager(scope)
    except Exception as err:
        console.print(f"[bold red]Scope Validation Failed:[/bold red] {err}")
        raise typer.Exit(code=1) from err

    table = Table(title=f"Validated Assessment Scope: {config_path}", border_style="cyan")
    table.add_column("Property", style="bold")
    table.add_column("Configured Value")

    table.add_row("Allowed Targets", ", ".join(scope.allowed_targets))
    table.add_row(
        "Excluded Targets",
        ", ".join(scope.excluded_targets) if scope.excluded_targets else "[dim]None[/dim]",
    )
    table.add_row("Allowed Ports", str(scope.allowed_ports))
    table.add_row("Total Allowed Ports Count", str(len(manager.allowed_ports)))
    table.add_row("Allow Public Targets", str(scope.allow_public_targets))
    table.add_row("Allow Cloud Metadata", str(scope.allow_cloud_metadata))
    table.add_row("Lab Mode", str(scope.lab_mode))
    if scope.description:
        table.add_row("Description", scope.description)

    console.print(table)
    console.print("[bold green]Scope definition is valid and enforceable.[/bold green]")


if __name__ == "__main__":
    app()
