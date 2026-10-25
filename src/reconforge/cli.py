"""Command-line interface for ReconForge."""

import asyncio
import json
import platform
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from reconforge import __version__
from reconforge.core.enums import PortState
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
from reconforge.utils.logging import setup_logging
from reconforge.utils.network import parse_ports

app = typer.Typer(
    name="reconforge",
    help="ReconForge: Intelligent Network Attack-Surface Mapping & Exposure Assessment Platform.",
    add_completion=False,
)
console = Console()


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
    ] = "21,22,25,53,80,110,143,443,445,3306,3389,5432,8080,8443",
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

    Strict scope allowlisting, DNS pinning, and bounded concurrency are enforced.
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
            "[cyan]Scanning target ports...", total=len(scan_targets) * len(parsed_ports)
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

    # 5. Output Presentation
    if json_output:
        out = {
            "summary": summary.model_dump(),
            "observations": [obs.model_dump(mode="json") for obs in observations],
        }
        console.print(json.dumps(out, indent=2))
        return

    # Rich Table Presentation
    table = Table(
        title=f"ReconForge TCP Assessment Results (Scan ID: {summary.scan_id[:8]})",
        border_style="dim",
    )
    table.add_column("Target IP", style="bold")
    table.add_column("Hostname", style="dim")
    table.add_column("Port", justify="right")
    table.add_column("State", justify="center")
    table.add_column("Latency (ms)", justify="right")
    table.add_column("Notes", style="italic")

    open_obs = [obs for obs in observations if obs.state == PortState.OPEN]
    other_obs = [obs for obs in observations if obs.state != PortState.OPEN]

    for obs in open_obs:
        table.add_row(
            obs.target_ip,
            obs.hostname or "-",
            str(obs.port),
            "[bold green]OPEN[/bold green]",
            f"{obs.response_time_ms:.1f}" if obs.response_time_ms else "-",
            "Handshake completed",
        )

    # If verbose, display closed/timeout/filtered rows
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
                obs.hostname or "-",
                str(obs.port),
                f"[{state_color}]{obs.state.value.upper()}[/{state_color}]",
                f"{obs.response_time_ms:.1f}" if obs.response_time_ms else "-",
                obs.error_message or "-",
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
