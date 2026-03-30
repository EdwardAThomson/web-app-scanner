"""CLI entry point for webscan."""

import sys

import click
from rich.console import Console
from rich.table import Table

from webscan.checklist import get_coverage_summary
from webscan.config import build_config
from webscan.dedup import deduplicate
from webscan.http_log import init_log, close_log
from webscan.models import Severity
from webscan.modules import DEFAULT_ORDER, MODULES
from webscan.report import print_summary, write_reports
from webscan.runner import run_scan
from webscan.utils import create_scan_dir

console = Console()


@click.group()
@click.version_option(package_name="webscan")
def cli():
    """webscan — Web application security testing orchestrator."""


@cli.command()
def check():
    """Show installation status of all scanner tools."""
    table = Table(title="webscan Tool Status")
    table.add_column("Module", style="bold")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Description")

    config = build_config()
    for name in DEFAULT_ORDER:
        module_cls = MODULES[name]
        module = module_cls(config)
        installed, info = module.check_installed()

        if installed:
            status = f"[green]installed[/green] ({info})"
            version = module.get_version()
        else:
            status = f"[red]MISSING[/red]"
            version = "-"

        table.add_row(name, module.tool_binary or "(built-in)", status, version, module.description)

    console.print(table)


@cli.command()
@click.argument("tools", nargs=-1)
@click.option("--force", is_flag=True, help="Re-install even if already present")
def install(tools, force):
    """Install external tools from source.

    Clones repos into tools/ and builds binaries into .venv/bin/.

    Examples:

        webscan install              # Install all missing tools

        webscan install nuclei ffuf  # Install specific tools

        webscan install --force      # Re-install everything
    """
    from webscan.installer import install_tool, install_all, check_prerequisites, TOOLS, VENV_BIN

    # Check prerequisites first
    prereqs = check_prerequisites()
    console.print("[bold]Prerequisites:[/bold]")
    for name, available in prereqs.items():
        status = "[green]available[/green]" if available else "[red]missing[/red]"
        console.print(f"  {name}: {status}")

    if not prereqs["git"]:
        console.print("\n[red]git is required. Install it first.[/red]")
        return

    if not prereqs["go"]:
        console.print("\n[yellow]Go is not installed. Go tools (nuclei, gitleaks, trivy, ffuf) will be skipped.[/yellow]")
        console.print("[dim]Install Go from https://go.dev/dl/ or run:[/dim]")
        console.print("[dim]  curl -sL https://go.dev/dl/go1.24.1.linux-amd64.tar.gz | tar -C $HOME -xz[/dim]")

    console.print()

    if force:
        # Remove existing binaries so install functions don't skip
        for name in (tools or TOOLS.keys()):
            if name in TOOLS:
                from webscan.modules import MODULES
                if name in MODULES:
                    mod = MODULES[name]({})
                    if mod.tool_binary:
                        binary = VENV_BIN / mod.tool_binary
                        if binary.is_file() or binary.is_symlink():
                            binary.unlink()

    if tools:
        # Install specific tools
        for name in tools:
            console.print(f"\n[bold]--- {name} ---[/bold]")
            install_tool(name)
    else:
        # Install all
        results = install_all()
        console.print("\n[bold]Summary:[/bold]")
        for name, success in results.items():
            status = "[green]OK[/green]" if success else "[red]FAILED[/red]"
            console.print(f"  {name}: {status}")


@cli.command()
@click.argument("modules", nargs=-1)
@click.option("-t", "--target", required=False, help="Target URL to scan")
@click.option("-s", "--source", "source_path", required=False, help="Source code path (for SAST/secret scanning)")
@click.option("-o", "--output", "output_dir", default="./webscan-results", help="Output directory for reports")
@click.option("-f", "--format", "formats", multiple=True, default=["json"],
              help="Report formats: json, html, md, csv (can be repeated, default: json)")
@click.option("-c", "--config", "config_file", required=False, help="Path to config YAML file")
@click.option("--skip", multiple=True, help="Modules to skip (can be repeated)")
@click.option("--serial", is_flag=True, help="Force sequential execution")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
              default=None, help="Exit with code 1 if findings at or above this severity exist (for CI)")
def run(modules, target, source_path, output_dir, formats, config_file, skip, serial, fail_on):
    """Run scan modules. Use 'all' for full scan.

    Examples:

        webscan run all -t https://example.com

        webscan run all -t https://example.com -f html -f csv

        webscan run headers -t https://example.com -f html

        webscan run gitleaks -s /path/to/repo
    """
    if not target and not source_path:
        raise click.UsageError("Provide --target (-t) for remote scanning or --source (-s) for local scanning")

    # Determine which modules to run
    if not modules or "all" in modules:
        module_names = list(DEFAULT_ORDER)
    else:
        # Validate module names
        for m in modules:
            if m not in MODULES:
                raise click.UsageError(
                    f"Unknown module '{m}'. Available: {', '.join(MODULES.keys())}"
                )
        module_names = list(modules)

    # Apply skip list
    module_names = [m for m in module_names if m not in skip]

    if not module_names:
        console.print("[yellow]No modules to run after applying skip list.[/yellow]")
        return

    # Build config (three-layer merge: defaults -> user yaml -> CLI flags)
    config = build_config(
        target=target,
        output_dir=output_dir,
        source_path=source_path,
        config_file=config_file,
    )

    # Create a timestamped sub-directory for all scan outputs
    scan_dir = create_scan_dir(output_dir)
    config["scan_dir"] = scan_dir

    # Filter modules by available targets and build (module, target) pairs
    module_targets: list[tuple[str, str]] = []
    skipped = []
    for name in module_names:
        mod_cls = MODULES[name]
        ttype = mod_cls.target_type
        if ttype == "url" and target:
            module_targets.append((name, target))
        elif ttype == "source" and source_path:
            module_targets.append((name, source_path))
        elif ttype == "both":
            module_targets.append((name, target or source_path))
        else:
            skipped.append((name, ttype))

    if skipped:
        for name, ttype in skipped:
            flag = "-t/--target" if ttype == "url" else "-s/--source"
            console.print(f"[yellow]Skipping {name} (needs {flag})[/yellow]")

    if not module_targets:
        console.print("[yellow]No modules to run with the provided targets.[/yellow]")
        return

    module_instances = [(MODULES[name](config), mt) for name, mt in module_targets]

    scan_label = " + ".join(filter(None, [target, source_path]))
    console.print(f"[bold]webscan[/bold] starting scan against [cyan]{scan_label}[/cyan]")
    console.print(f"Modules: {', '.join(name for name, _ in module_targets)}")
    console.print()

    # Initialize HTTP request/response logging inside the scan directory
    http_log_path, http_log_readable = init_log(scan_dir)

    # Run the scan (parallel by default, --serial for sequential)
    scan_result = run_scan(module_instances, target or source_path, serial=serial)

    # Close HTTP log
    close_log()

    # Print summary (raw counts)
    print_summary(scan_result)

    # Cross-module deduplication for reports
    raw_count = len(scan_result.all_findings)
    deduped_findings = deduplicate(scan_result.all_findings)
    deduped_count = len(deduped_findings)
    removed = raw_count - deduped_count
    if removed > 0:
        console.print(f"[dim]Deduplication: {raw_count} raw findings → {deduped_count} unique ({removed} duplicates merged)[/dim]")

    # Checklist coverage — pass finding titles so we can match against specific checklist items
    modules_run = [name for name, _ in module_targets]
    finding_titles = [f.title for f in scan_result.all_findings]
    checklist_summary = get_coverage_summary(modules_run, finding_titles)
    console.print(f"\n[bold]Checklist:[/bold] {checklist_summary['tested']} items tested "
                  f"({checklist_summary['with_issues']} with issues, {checklist_summary['passed']} passed) "
                  f"of {checklist_summary['total_items']} total")

    # Write reports inside the scan directory
    report_paths = write_reports(scan_result, scan_dir, list(formats), checklist_summary,
                                 deduped_findings=deduped_findings)

    console.print()
    console.print(f"[bold green]Scan directory:[/bold green] {scan_dir}")
    for fmt, path in report_paths.items():
        console.print(f"  {fmt.upper()} report: {path}")
    console.print(f"  HTTP log: {http_log_readable}")
    console.print(f"  HTTP log (JSONL): {http_log_path}")

    # Severity-based exit codes for CI pipelines
    if fail_on:
        threshold = Severity(fail_on.lower())
        threshold_rank = Severity.rank(threshold)
        worst = max(
            (Severity.rank(f.severity) for f in scan_result.all_findings),
            default=-1,
        )
        if worst >= threshold_rank:
            console.print(
                f"\n[bold red]FAIL:[/bold red] findings at or above "
                f"'{threshold.value}' severity detected (exit code 1)"
            )
            sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
