"""Scan execution engine."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from webscan.models import ModuleResult, ScanResult
from webscan.modules import PARALLEL_GROUPS
from webscan.modules.base import BaseModule

console = Console()


def _run_one(module: BaseModule, target: str) -> ModuleResult:
    """Run a single module. Used as the unit of work for both serial and parallel."""
    return module.run(target)


def run_modules_serial(
    module_targets: list[tuple[BaseModule, str]], show_progress: bool = True
) -> list[ModuleResult]:
    """Run modules sequentially with progress display."""
    results = []

    if show_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            for module, target in module_targets:
                task = progress.add_task(f"Running {module.name}...", total=None)
                result = module.run(target)
                results.append(result)
                status = "[green]done" if result.success else f"[red]failed: {result.error}"
                progress.update(task, description=f"{module.name} {status}")
                progress.stop_task(task)
    else:
        for module, target in module_targets:
            results.append(module.run(target))

    return results


def run_modules_parallel(
    module_targets: list[tuple[BaseModule, str]], show_progress: bool = True
) -> list[ModuleResult]:
    """Run modules in parallel groups.

    Modules within a group run concurrently. Groups run sequentially
    (later groups may depend on earlier results).
    """
    # Build a lookup: module_name -> (module, target)
    mt_lookup = {mod.name: (mod, tgt) for mod, tgt in module_targets}
    requested_names = set(mt_lookup.keys())
    results = []

    if show_progress:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            for group in PARALLEL_GROUPS:
                # Filter to modules in this group that were actually requested
                group_items = [(mt_lookup[name]) for name in group if name in requested_names]
                if not group_items:
                    continue

                # Create progress tasks for each module in the group
                progress_tasks = {}
                for mod, _tgt in group_items:
                    progress_tasks[mod.name] = progress.add_task(
                        f"Running {mod.name}...", total=None
                    )

                # Run the group in parallel
                with ThreadPoolExecutor(max_workers=len(group_items)) as executor:
                    futures = {
                        executor.submit(_run_one, mod, tgt): mod
                        for mod, tgt in group_items
                    }
                    for future in as_completed(futures):
                        mod = futures[future]
                        try:
                            result = future.result()
                        except Exception as e:
                            result = ModuleResult(
                                module_name=mod.name, success=False, error=str(e)
                            )
                        results.append(result)
                        status = "[green]done" if result.success else f"[red]failed: {result.error}"
                        progress.update(
                            progress_tasks[mod.name],
                            description=f"{mod.name} {status}",
                        )
                        progress.stop_task(progress_tasks[mod.name])
    else:
        for group in PARALLEL_GROUPS:
            group_items = [mt_lookup[name] for name in group if name in requested_names]
            if not group_items:
                continue
            with ThreadPoolExecutor(max_workers=len(group_items)) as executor:
                futures = {
                    executor.submit(_run_one, mod, tgt): mod
                    for mod, tgt in group_items
                }
                for future in as_completed(futures):
                    mod = futures[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = ModuleResult(
                            module_name=mod.name, success=False, error=str(e)
                        )
                    results.append(result)

    return results


def run_scan(
    module_targets: list[tuple[BaseModule, str]],
    scan_label: str,
    serial: bool = False,
    show_progress: bool = True,
) -> ScanResult:
    """Run a full scan and return the aggregated result."""
    scan = ScanResult(target=scan_label, started_at=datetime.now())

    if serial:
        scan.module_results = run_modules_serial(module_targets, show_progress)
    else:
        scan.module_results = run_modules_parallel(module_targets, show_progress)

    scan.finished_at = datetime.now()
    return scan
