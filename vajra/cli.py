"""Vajra CLI — the command-line interface."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console

from vajra import __version__
from vajra.config import (
    DEFAULT_DASHBOARD_DIR,
    DEFAULT_DB_PATH,
    DEFAULT_VERSION_SCAN_COUNT,
    DEFAULT_WATCH_COUNT,
    FILE_COUNT_DELTA_THRESHOLD,
)
from vajra.diff import normalize_tree, run_audit
from vajra.github import (
    check_rate_limit,
    download_tag_archive,
    find_matching_tag,
)
from vajra.models import (
    AuditResult,
    MaintainerInfo,
    Verdict,
    VersionScanResult,
)
from vajra.pypi import (
    download_and_extract,
    extract_github_repo,
    fetch_metadata,
    find_sdist_url,
    get_all_versions,
)
from vajra.reporter import print_audit, print_audit_json, print_version_scan

console = Console(stderr=True)

app = typer.Typer(
    name="vajra",
    help="Detect Source-to-Artifact Drift in Python packages.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vajra {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Vajra — Source-to-Artifact Drift Detector."""


# ---------------------------------------------------------------------------
# vajra check
# ---------------------------------------------------------------------------

@app.command()
def check(
    package: str = typer.Argument(help="PyPI package name (e.g. 'litellm')"),
    version: str = typer.Argument(help="Package version to audit (e.g. '1.82.8')"),
    check_all_versions: bool = typer.Option(
        False,
        "--check-all-versions",
        help="Scan the last N versions for sudden changes.",
    ),
    num_versions: int = typer.Option(
        DEFAULT_VERSION_SCAN_COUNT,
        "--num-versions",
        "-n",
        help="Number of recent versions to scan with --check-all-versions.",
    ),
    triage: bool = typer.Option(
        False,
        "--triage",
        help="Run AI triage (Anthropic Claude) on flagged diffs.",
    ),
    test_mode: bool = typer.Option(
        False,
        "--test-mode",
        help="Use local samples/ directory instead of fetching from network.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show all files including clean matches.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output results as JSON.",
    ),
) -> None:
    """Audit a PyPI package for source-to-artifact drift."""
    if test_mode:
        result = _run_test_mode(package, version)
        if triage and result.verdict != Verdict.CLEAN:
            _run_triage_on_test(result, package, version)
        if json_output:
            print_audit_json(result)
        else:
            print_audit(result, verbose=verbose)
        _exit_with_code(result.verdict)
        return

    if check_all_versions:
        scan = asyncio.run(_run_version_scan(package, version, num_versions, verbose))
        print_version_scan(scan)
        worst = max(
            (a.verdict for a in scan.audits),
            key=lambda v: [Verdict.CLEAN, Verdict.WARN, Verdict.CRITICAL].index(v),
            default=Verdict.CLEAN,
        )
        _exit_with_code(worst)
        return

    result = asyncio.run(_run_audit(package, version, enable_triage=triage))
    if json_output:
        print_audit_json(result)
    else:
        print_audit(result, verbose=verbose)
    _exit_with_code(result.verdict)


# ---------------------------------------------------------------------------
# vajra watch
# ---------------------------------------------------------------------------

@app.command()
def watch(
    top: int = typer.Option(
        DEFAULT_WATCH_COUNT,
        "--top",
        "-t",
        help="Scan the top N most-downloaded PyPI packages.",
    ),
    include_ai: bool = typer.Option(
        False,
        "--include-ai",
        help="Also scan curated AI/ML packages (LLM SDKs, agents, ML libs, vector DBs, etc.).",
    ),
    packages_file: Optional[Path] = typer.Option(
        None,
        "--packages-file",
        "-f",
        help="Scan packages from a text file (one per line).",
    ),
    triage_flag: bool = typer.Option(
        False,
        "--triage",
        help="Run AI triage on flagged packages.",
    ),
    dashboard_flag: bool = typer.Option(
        False,
        "--dashboard",
        help="Regenerate static dashboard after scanning.",
    ),
    db: Optional[Path] = typer.Option(
        None,
        "--db",
        help=f"SQLite database path (default: {DEFAULT_DB_PATH}).",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help=f"Dashboard output directory (default: {DEFAULT_DASHBOARD_DIR}).",
    ),
) -> None:
    """Batch-scan top PyPI packages for source-to-artifact drift."""
    from vajra.ai_packages import get_ai_packages
    from vajra.store import VajraStore
    from vajra.watch import fetch_top_packages, load_packages_file, run_watch

    with VajraStore(db or DEFAULT_DB_PATH) as store:
        if packages_file:
            if not packages_file.exists():
                console.print(f"[red]File not found: {packages_file}[/red]")
                raise typer.Exit(1)
            packages = load_packages_file(packages_file)
            console.print(f"[cyan]Loaded {len(packages)} packages from {packages_file}[/cyan]")
        else:
            console.print(f"[cyan]Fetching top {top} PyPI packages...[/cyan]")
            packages = asyncio.run(_fetch_packages(top))

        if include_ai:
            ai_pkgs = get_ai_packages()
            existing = {p.lower() for p in packages}
            new_ai = [p for p in ai_pkgs if p.lower() not in existing]
            packages.extend(new_ai)
            console.print(
                f"[cyan]Added {len(new_ai)} AI/ML packages "
                f"({len(ai_pkgs)} curated, {len(ai_pkgs) - len(new_ai)} already in top-{top})[/cyan]"
            )

        if not packages:
            console.print("[red]No packages to scan.[/red]")
            raise typer.Exit(1)

        console.print(f"[bold cyan]Total packages to scan: {len(packages)}[/bold cyan]")

        result = asyncio.run(
            run_watch(packages, enable_triage=triage_flag, store=store)
        )

        console.print(f"\n[bold]Watch complete:[/bold]")
        console.print(f"  Scanned: {result.packages_scanned}")
        console.print(f"  Drift found: {result.drift_found}")

        if dashboard_flag:
            from vajra.dashboard import generate_dashboard
            generate_dashboard(store, output_dir or DEFAULT_DASHBOARD_DIR)


# ---------------------------------------------------------------------------
# vajra dashboard
# ---------------------------------------------------------------------------

@app.command()
def dashboard(
    db: Optional[Path] = typer.Option(
        None,
        "--db",
        help=f"SQLite database path (default: {DEFAULT_DB_PATH}).",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help=f"Output directory (default: {DEFAULT_DASHBOARD_DIR}).",
    ),
) -> None:
    """Generate a static dashboard from existing scan data."""
    from vajra.dashboard import generate_dashboard
    from vajra.store import VajraStore

    db_path = db or DEFAULT_DB_PATH
    if not db_path.exists():
        console.print(
            f"[red]Database not found: {db_path}[/red]\n"
            "[dim]Run 'vajra watch' first to populate scan data.[/dim]"
        )
        raise typer.Exit(1)

    with VajraStore(db_path) as store:
        out = generate_dashboard(store, output_dir or DEFAULT_DASHBOARD_DIR)
        console.print(f"[green]Dashboard ready at: {out}/index.html[/green]")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _fetch_packages(count: int) -> list[str]:
    from vajra.watch import fetch_top_packages
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await fetch_top_packages(client, count)


def _run_test_mode(package: str, version: str) -> AuditResult:
    """Run audit against local sample directories."""
    samples_dir = Path(__file__).resolve().parent.parent / "samples"

    github_dir = samples_dir / f"{package}_{version.replace('.', '_')}_github"
    pypi_dir = samples_dir / f"{package}_{version.replace('.', '_')}_pypi"

    if not github_dir.exists() or not pypi_dir.exists():
        github_dir = samples_dir / f"{package}_{version.replace('.', '_')}"
        pypi_dir = github_dir
        legacy = True
    else:
        legacy = False

    if not github_dir.exists():
        console.print(
            f"[red]Sample directory not found: {github_dir}[/red]"
        )
        raise typer.Exit(1)

    if legacy:
        console.print(
            "[yellow]Test mode: using single sample directory as both sources.[/yellow]"
        )
        pypi_tree = normalize_tree(pypi_dir)
        github_tree = pypi_tree.copy()
    else:
        console.print(
            f"[cyan]Test mode: comparing[/cyan]\n"
            f"  PyPI:   {pypi_dir}\n"
            f"  GitHub: {github_dir}"
        )
        pypi_tree = normalize_tree(pypi_dir)
        github_tree = normalize_tree(github_dir)

    return run_audit(
        pypi_tree=pypi_tree,
        github_tree=github_tree,
        package=package,
        version=version,
        github_repo=f"(test-mode)",
        github_tag=f"v{version}",
        github_tag_exists=True,
    )


def _run_triage_on_test(result: AuditResult, package: str, version: str) -> None:
    """Run AI triage using test-mode sample directories."""
    from vajra.triage import triage_audit

    samples_dir = Path(__file__).resolve().parent.parent / "samples"
    pypi_dir = samples_dir / f"{package}_{version.replace('.', '_')}_pypi"
    github_dir = samples_dir / f"{package}_{version.replace('.', '_')}_github"

    if pypi_dir.exists() and github_dir.exists():
        verdicts = asyncio.run(triage_audit(result, pypi_dir, github_dir))
        if verdicts:
            from vajra.reporter import print_triage_verdicts
            print_triage_verdicts(verdicts)


async def _run_audit(
    package: str, version: str, enable_triage: bool = False
) -> AuditResult:
    """Full network audit: fetch from PyPI + GitHub, compare."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        with console.status("[cyan]Fetching PyPI metadata..."):
            try:
                metadata = await fetch_metadata(client, package, version)
            except httpx.HTTPStatusError as e:
                console.print(f"[red]PyPI error: {e.response.status_code} for {package}=={version}[/red]")
                raise typer.Exit(1)

        sdist_url = find_sdist_url(metadata, version)
        if not sdist_url:
            console.print(f"[red]No source distribution found for {package}=={version}[/red]")
            raise typer.Exit(1)

        repo_info = extract_github_repo(metadata)
        if not repo_info:
            console.print(
                f"[red]Could not find a GitHub repository in PyPI metadata for {package}.[/red]\n"
                "[dim]Tip: not all packages link to GitHub in their metadata.[/dim]"
            )
            raise typer.Exit(1)

        owner, repo = repo_info
        github_repo_str = f"{owner}/{repo}"
        console.print(f"[cyan]Resolved GitHub repo:[/cyan] {github_repo_str}")

        await check_rate_limit(client)

        with console.status("[cyan]Finding matching GitHub tag..."):
            tag = await find_matching_tag(client, owner, repo, package, version)

        github_tag_exists = tag is not None
        if not tag:
            console.print(
                f"[bold red]No GitHub tag found for version {version}![/bold red]\n"
                f"[dim]Tried: v{version}, {version}, {package}-{version}[/dim]"
            )

        with tempfile.TemporaryDirectory(prefix="vajra_") as tmpdir:
            tmp = Path(tmpdir)
            pypi_dest = tmp / "pypi"
            pypi_dest.mkdir()

            console.print(f"[cyan]Downloading PyPI sdist...[/cyan]")
            pypi_extracted = await download_and_extract(client, sdist_url, pypi_dest)

            if tag:
                gh_dest = tmp / "github"
                gh_dest.mkdir()
                console.print(f"[cyan]Downloading GitHub source (tag: {tag})...[/cyan]")
                gh_extracted = await download_tag_archive(
                    client, owner, repo, tag, gh_dest
                )
                github_tree = normalize_tree(gh_extracted)
            else:
                github_tree = {}
                gh_extracted = tmp / "empty"
                gh_extracted.mkdir(exist_ok=True)

            pypi_tree = normalize_tree(pypi_extracted)

            result = run_audit(
                pypi_tree=pypi_tree,
                github_tree=github_tree,
                package=package,
                version=version,
                github_repo=github_repo_str,
                github_tag=tag or "(none)",
                github_tag_exists=github_tag_exists,
            )

            if enable_triage and result.verdict != Verdict.CLEAN:
                from vajra.triage import triage_audit
                verdicts = await triage_audit(result, pypi_extracted, gh_extracted)
                if verdicts:
                    from vajra.reporter import print_triage_verdicts
                    print_triage_verdicts(verdicts)

            return result


async def _run_version_scan(
    package: str,
    anchor_version: str,
    count: int,
    verbose: bool,
) -> VersionScanResult:
    """Scan multiple versions for drift and maintainer changes."""
    scan = VersionScanResult(package=package)

    async with httpx.AsyncClient(timeout=60.0) as client:
        with console.status("[cyan]Fetching version list..."):
            all_versions = await get_all_versions(client, package)

        if not all_versions:
            console.print(f"[red]No versions found for {package}[/red]")
            raise typer.Exit(1)

        try:
            anchor_idx = all_versions.index(anchor_version)
        except ValueError:
            anchor_idx = 0

        start = max(0, anchor_idx - count + 1)
        selected = all_versions[start : start + count]
        if not selected:
            selected = all_versions[:count]

        scan.versions_scanned = selected
        console.print(f"[cyan]Scanning versions:[/cyan] {', '.join(selected)}")

        prev_file_count: int | None = None

        for ver in selected:
            console.print(f"\n[bold]--- Auditing {package}=={ver} ---[/bold]")

            with console.status(f"[cyan]Fetching metadata for {ver}..."):
                try:
                    metadata = await fetch_metadata(client, package, ver)
                except httpx.HTTPStatusError:
                    console.print(f"[yellow]Skipping {ver}: not found on PyPI[/yellow]")
                    continue

            info = metadata.get("info", {})
            mi = MaintainerInfo(
                version=ver,
                author=info.get("author") or "",
                author_email=info.get("author_email") or "",
                maintainer=info.get("maintainer") or "",
                maintainer_email=info.get("maintainer_email") or "",
            )
            scan.maintainer_history.append(mi)

            sdist_url = find_sdist_url(metadata, ver)
            repo_info = extract_github_repo(metadata)

            if not sdist_url or not repo_info:
                console.print(f"[yellow]Skipping {ver}: missing sdist or repo info[/yellow]")
                continue

            owner, repo = repo_info
            await check_rate_limit(client)
            tag = await find_matching_tag(client, owner, repo, package, ver)

            with tempfile.TemporaryDirectory(prefix="vajra_") as tmpdir:
                tmp = Path(tmpdir)
                pypi_dest = tmp / "pypi"
                pypi_dest.mkdir()

                pypi_extracted = await download_and_extract(
                    client, sdist_url, pypi_dest, show_progress=False
                )

                if tag:
                    gh_dest = tmp / "github"
                    gh_dest.mkdir()
                    gh_extracted = await download_tag_archive(
                        client, owner, repo, tag, gh_dest, show_progress=False
                    )
                    github_tree = normalize_tree(gh_extracted)
                else:
                    github_tree = {}

                pypi_tree = normalize_tree(pypi_extracted)

                result = run_audit(
                    pypi_tree=pypi_tree,
                    github_tree=github_tree,
                    package=package,
                    version=ver,
                    github_repo=f"{owner}/{repo}",
                    github_tag=tag or "(none)",
                    github_tag_exists=tag is not None,
                )
                scan.audits.append(result)

                current_count = result.pypi_file_count
                if prev_file_count is not None and prev_file_count > 0:
                    delta = abs(current_count - prev_file_count) / prev_file_count
                    if delta > FILE_COUNT_DELTA_THRESHOLD:
                        note = (
                            f"v{ver}: file count changed from {prev_file_count} "
                            f"to {current_count} ({delta:.0%} delta)"
                        )
                        scan.file_count_anomalies.append(note)
                prev_file_count = current_count

        if len(scan.maintainer_history) >= 2:
            for i in range(1, len(scan.maintainer_history)):
                prev = scan.maintainer_history[i - 1]
                curr = scan.maintainer_history[i]
                if (prev.author, prev.author_email) != (
                    curr.author,
                    curr.author_email,
                ) or (prev.maintainer != curr.maintainer):
                    scan.maintainer_changed = True
                    break

    return scan


def _exit_with_code(verdict: Verdict) -> None:
    if verdict == Verdict.CRITICAL:
        raise typer.Exit(2)
    if verdict == Verdict.WARN:
        raise typer.Exit(1)
