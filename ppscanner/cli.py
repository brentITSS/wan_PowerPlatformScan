from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from ppscanner.auth import AuthenticationError, Settings, acquire_access_tokens
from ppscanner.client import PowerPlatformAdminClient, PowerPlatformApiError
from ppscanner.collectors import (
    collect_app_managed_statuses,
    collect_app_permissions,
    collect_apps,
    collect_connections,
    collect_dataverse_inventory,
    collect_dlp_policies,
    collect_environment_access,
    collect_flows,
)
from ppscanner.compare import compare_snapshots
from ppscanner.findings import evaluate_findings
from ppscanner.models import Environment
from ppscanner.narrative import build_sections
from ppscanner.report import write_csv_report, write_html_report, write_json_report
from ppscanner.snapshot import (
    create_snapshot,
    latest_snapshot_path,
    read_snapshot,
    save_snapshot,
    utc_now,
)

app = typer.Typer(
    help="Read-only inventory of Microsoft Power Platform environments.",
    no_args_is_help=True,
)
console = Console()
error_console = Console(stderr=True)


@app.callback()
def main() -> None:
    """Read-only inventory of Microsoft Power Platform environments."""


@app.command()
def scan(
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Directory where the timestamped JSON snapshot will be saved.",
            file_okay=False,
        ),
    ] = Path(".data/snapshots"),
) -> None:
    """Sign in, list tenant-admin environments, and save a snapshot."""
    try:
        settings = Settings.from_environment()
        access_tokens = acquire_access_tokens(settings)
        started_at = utc_now()
        with PowerPlatformAdminClient(
            access_tokens.power_platform,
            access_tokens.power_apps_service,
        ) as client:
            environments = [
                Environment.from_api(item) for item in client.list_environments()
            ]
            environments = collect_apps(client, environments)
            environments = collect_app_permissions(client, environments)
            environments = collect_environment_access(client, environments)
            environments = collect_connections(client, environments)
            environments = collect_app_managed_statuses(
                client,
                environments,
                access_tokens.acquire_dataverse_token,
            )
            environments = collect_flows(
                client,
                environments,
                access_tokens.power_automate,
                access_tokens.power_automate_error,
            )
            environments = collect_dataverse_inventory(
                client,
                environments,
                access_tokens.acquire_dataverse_token,
            )
            dlp_policies, dlp_status, dlp_error = collect_dlp_policies(client)
        findings = evaluate_findings(
            environments,
            dlp_policies,
            dlp_status,
            started_at.isoformat(),
        )
        snapshot = create_snapshot(
            settings.tenant_id,
            started_at,
            environments,
            dlp_policies=dlp_policies,
            dlp_collection_status=dlp_status,
            dlp_collection_error=dlp_error,
            findings=findings,
        )
        snapshot_path = save_snapshot(snapshot, output_dir)
    except (AuthenticationError, PowerPlatformApiError, OSError) as error:
        error_console.print(f"[bold red]Scan failed:[/] {error}")
        raise typer.Exit(code=1) from error

    total_apps = sum(len(environment.apps) for environment in environments)
    complete_apps = sum(
        environment.apps_collection_status == "complete" for environment in environments
    )
    console.print(
        f"Tenant-admin scan completed for [bold]{len(environments)}[/] "
        f"environments; "
        f"app inventory collected for [bold]{complete_apps}[/] of them, "
        f"with [bold]{total_apps}[/] apps and managed status assessed for "
        f"[bold]{sum(app.managed_status != 'not_assessed' for env in environments for app in env.apps)}[/]. "
        f"Cloud flows: [bold]{sum(len(environment.flows) for environment in environments)}[/]. "
        f"Solutions: [bold]{sum(len(environment.solutions) for environment in environments)}[/]. "
        f"DLP policies: [bold]{len(dlp_policies)}[/] ({dlp_status}). "
        f"Findings: [bold]{len(findings)}[/]."
    )
    console.print(
        "[yellow]Coverage note:[/] tenant environment discovery and app "
        "inventory APIs are documented as preview. Environment discovery is "
        "tenant-admin scoped and requires an appropriately assigned admin "
        "role. Managed status is read from Dataverse app records and requires "
        "Dataverse delegated access. A short result is not proof that the "
        "tenant contains no other resources."
    )
    for environment in snapshot.environments:
        if environment.apps_collection_error:
            error_console.print(
                f"[yellow]App inventory {environment.apps_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.apps_collection_error}"
            )
        if environment.app_managed_status_collection_error:
            error_console.print(
                f"[yellow]Managed status "
                f"{environment.app_managed_status_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.app_managed_status_collection_error}"
            )
        if environment.flows_collection_error:
            error_console.print(
                f"[yellow]Cloud flow inventory {environment.flows_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.flows_collection_error}"
            )
        if environment.solutions_collection_error:
            error_console.print(
                f"[yellow]Solution inventory {environment.solutions_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.solutions_collection_error}"
            )
        if environment.connection_references_collection_error:
            error_console.print(
                f"[yellow]Connection reference inventory "
                f"{environment.connection_references_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.connection_references_collection_error}"
            )
        if environment.app_permissions_collection_error:
            error_console.print(
                f"[yellow]App sharing "
                f"{environment.app_permissions_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.app_permissions_collection_error}"
            )
        if environment.role_assignments_collection_error:
            error_console.print(
                f"[yellow]Environment access "
                f"{environment.role_assignments_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.role_assignments_collection_error}"
            )
        if environment.connections_collection_error:
            error_console.print(
                f"[yellow]Connections "
                f"{environment.connections_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.connections_collection_error}"
            )
        if environment.flow_owner_collection_error:
            error_console.print(
                f"[yellow]Flow owners "
                f"{environment.flow_owner_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.flow_owner_collection_error}"
            )
        if environment.solution_membership_collection_error:
            error_console.print(
                f"[yellow]Solution membership "
                f"{environment.solution_membership_collection_status}[/] "
                f"for {environment.display_name or environment.id}: "
                f"{environment.solution_membership_collection_error}"
            )
    if snapshot.dlp_collection_error:
        error_console.print(
            f"[yellow]DLP policies {snapshot.dlp_collection_status}[/]: "
            f"{snapshot.dlp_collection_error}"
        )
    console.print(f"Snapshot: {snapshot_path.resolve()}")
    _print_report(snapshot.to_dict())


def _print_findings(snapshot: dict[str, object]) -> None:
    findings = snapshot.get("findings")
    if not isinstance(findings, list) or not findings:
        console.print("Findings: none stored in this snapshot.")
        return
    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Environment")
    table.add_column("Resource")
    table.add_column("Summary")
    table.add_column("Recommendation")
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        table.add_row(
            str(finding.get("severity") or ""),
            str(finding.get("status") or ""),
            str(finding.get("environment_name") or ""),
            str(finding.get("resource_name") or ""),
            str(finding.get("summary") or ""),
            str(finding.get("recommendation") or ""),
        )
    console.print(table)


def _snapshot_path(snapshot: Path | None, snapshots_dir: Path) -> Path:
    if snapshot is not None:
        return snapshot
    latest = latest_snapshot_path(snapshots_dir)
    if latest is None:
        error_console.print(
            "[bold red]No snapshots found.[/] Run python -m ppscanner scan first."
        )
        raise typer.Exit(code=1)
    return latest


def _load(path: Path) -> dict[str, object]:
    try:
        return read_snapshot(path)
    except (ValueError, TypeError) as error:
        error_console.print(f"[bold red]Could not read snapshot:[/] {error}")
        raise typer.Exit(code=1) from error


@app.command()
def environments(
    snapshot: Annotated[
        Path | None,
        typer.Option("--snapshot", help="Snapshot JSON file. Defaults to the latest."),
    ] = None,
    snapshots_dir: Annotated[
        Path,
        typer.Option("--snapshots-dir", help="Directory to search for the latest snapshot."),
    ] = Path(".data/snapshots"),
) -> None:
    """Show the maturity report for a saved snapshot."""
    _print_report(_load(_snapshot_path(snapshot, snapshots_dir)))


def _print_report(snapshot: dict[str, object]) -> None:
    console.print(
        f"Snapshot {snapshot.get('snapshot_id')} "
        f"completed {snapshot.get('completed_at')}."
    )
    for section in build_sections(snapshot):
        console.print(f"\n[bold]{section.title}[/]")
        for fact in section.facts:
            console.print(fact)
        if section.rows:
            table = Table(title=section.title)
            for header in section.headers:
                table.add_column(header, overflow="fold")
            for row in section.rows:
                table.add_row(*row)
            console.print(table)
        console.print(f"[bold]Recommendation.[/] {section.recommendation}")


@app.command()
def findings(
    snapshot: Annotated[Path | None, typer.Option("--snapshot")] = None,
    snapshots_dir: Annotated[Path, typer.Option("--snapshots-dir")] = Path(
        ".data/snapshots"
    ),
    severity: Annotated[
        str | None,
        typer.Option("--severity", help="Filter by critical, high, medium, low, or informational."),
    ] = None,
) -> None:
    """Show findings stored in a snapshot."""
    payload = _load(_snapshot_path(snapshot, snapshots_dir))
    if "findings" not in payload:
        error_console.print(
            "This snapshot has no evaluated findings. Run a new scan to assess them."
        )
        raise typer.Exit(code=1)
    stored = payload.get("findings")
    if isinstance(stored, list) and severity:
        payload = {
            **payload,
            "findings": [
                finding
                for finding in stored
                if isinstance(finding, dict) and finding.get("severity") == severity
            ],
        }
    _print_findings(payload)


@app.command()
def report(
    snapshot: Annotated[Path | None, typer.Option("--snapshot")] = None,
    snapshots_dir: Annotated[Path, typer.Option("--snapshots-dir")] = Path(
        ".data/snapshots"
    ),
    output_format: Annotated[
        str,
        typer.Option("--format", help="json, csv, or html."),
    ] = "html",
    output: Annotated[
        Path | None,
        typer.Option("--output", help="File for json/html, or directory for csv."),
    ] = None,
) -> None:
    """Export a snapshot as JSON, CSV, or HTML."""
    path = _snapshot_path(snapshot, snapshots_dir)
    payload = _load(path)
    snapshot_id = str(payload.get("snapshot_id") or path.stem)
    normalized = output_format.casefold()
    if normalized == "json":
        target = output or Path(".data/reports") / f"{snapshot_id}.json"
        written = write_json_report(payload, target)
    elif normalized == "csv":
        target = output or Path(".data/reports") / snapshot_id
        written = write_csv_report(payload, target)
    elif normalized == "html":
        target = output or Path(".data/reports") / f"{snapshot_id}.html"
        written = write_html_report(payload, target)
    else:
        error_console.print("Format must be json, csv, or html.")
        raise typer.Exit(code=1)
    console.print(f"Report: {written.resolve()}")


@app.command()
def compare(
    baseline: Annotated[Path, typer.Argument(help="Earlier snapshot JSON file.")],
    current: Annotated[Path, typer.Argument(help="Later snapshot JSON file.")],
) -> None:
    """Summarize changes between two snapshots."""
    result = compare_snapshots(_load(baseline), _load(current))
    console.print(
        f"Compared [bold]{result['baseline_snapshot_id']}[/] "
        f"to [bold]{result['current_snapshot_id']}[/]."
    )
    for limitation in result["limitations"]:
        error_console.print(f"[yellow]Limitation:[/] {limitation}")
    for name in ("environments", "apps", "flows", "solutions", "findings"):
        section = result[name]
        console.print(
            f"{name}: {len(section['added'])} added, "
            f"{len(section['removed'])} removed, {len(section['changed'])} changed."
        )


@app.command()
def serve(
    port: Annotated[int, typer.Option("--port")] = 8000,
    snapshots_dir: Annotated[Path, typer.Option("--snapshots-dir")] = Path(
        ".data/snapshots"
    ),
) -> None:
    """Open the local dashboard at http://127.0.0.1."""
    import uvicorn

    from ppscanner.web import create_app

    console.print(f"Dashboard: http://127.0.0.1:{port}")
    uvicorn.run(
        create_app(snapshots_dir),
        host="127.0.0.1",
        port=port,
        log_level="info",
    )
