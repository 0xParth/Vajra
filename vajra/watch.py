"""Batch scanner — watch top PyPI packages for drift."""

from __future__ import annotations

import asyncio
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console

from vajra.config import TOP_PACKAGES_URL
from vajra.diff import normalize_tree, run_audit
from vajra.github import (
    check_rate_limit,
    download_tag_archive,
    find_matching_tag,
)
from vajra.models import AuditResult, Verdict, WatchResult
from vajra.pypi import (
    download_and_extract,
    extract_github_repo,
    fetch_metadata,
    find_sdist_url,
)
from vajra.store import VajraStore
from vajra.triage import triage_audit

console = Console(stderr=True)

_SEMAPHORE_LIMIT = 3  # concurrent audits (respects GitHub rate limits)


async def fetch_top_packages(
    client: httpx.AsyncClient, count: int
) -> list[str]:
    """Fetch the top *count* PyPI packages by download count."""
    resp = await client.get(TOP_PACKAGES_URL, follow_redirects=True)
    resp.raise_for_status()
    data = resp.json()
    rows = data.get("rows", [])
    return [r["project"] for r in rows[:count]]


def load_packages_file(path: Path) -> list[str]:
    """Load package names from a text file (one per line)."""
    packages = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            packages.append(line.split("==")[0].split(">=")[0].strip())
    return packages


async def audit_single_package(
    client: httpx.AsyncClient,
    package: str,
    semaphore: asyncio.Semaphore,
    store: VajraStore | None = None,
    enable_triage: bool = False,
) -> AuditResult | None:
    """Audit the latest version of a single package."""
    async with semaphore:
        try:
            metadata = await fetch_metadata(client, package)
        except httpx.HTTPStatusError:
            console.print(f"[yellow]  Skip {package}: not found on PyPI[/yellow]")
            return None

        info = metadata.get("info", {})
        version = info.get("version", "")
        if not version:
            console.print(f"[yellow]  Skip {package}: no version info[/yellow]")
            return None

        if store and store.has_scan(package, version):
            console.print(f"[dim]  Skip {package}=={version}: already scanned[/dim]")
            return None

        sdist_url = find_sdist_url(metadata, version)
        if not sdist_url:
            console.print(f"[yellow]  Skip {package}=={version}: no sdist[/yellow]")
            return None

        repo_info = extract_github_repo(metadata)
        if not repo_info:
            console.print(f"[yellow]  Skip {package}: no GitHub repo in metadata[/yellow]")
            return None

        owner, repo = repo_info
        await check_rate_limit(client)
        tag = await find_matching_tag(client, owner, repo, package, version)

        with tempfile.TemporaryDirectory(prefix="vajra_") as tmpdir:
            tmp = Path(tmpdir)
            pypi_dest = tmp / "pypi"
            pypi_dest.mkdir()

            try:
                pypi_extracted = await download_and_extract(
                    client, sdist_url, pypi_dest, show_progress=False
                )
            except Exception as e:
                console.print(f"[yellow]  Skip {package}=={version}: download failed ({e})[/yellow]")
                return None

            if tag:
                gh_dest = tmp / "github"
                gh_dest.mkdir()
                try:
                    gh_extracted = await download_tag_archive(
                        client, owner, repo, tag, gh_dest, show_progress=False
                    )
                    github_tree = normalize_tree(gh_extracted)
                except Exception as e:
                    console.print(f"[yellow]  Skip {package}=={version}: GitHub download failed ({e})[/yellow]")
                    return None
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
                github_repo=f"{owner}/{repo}",
                github_tag=tag or "(none)",
                github_tag_exists=tag is not None,
            )

            triage_verdicts = None
            if enable_triage and result.verdict != Verdict.CLEAN:
                triage_verdicts = await triage_audit(
                    result, pypi_extracted, gh_extracted
                )

            if store:
                store.save_scan(result, triage_verdicts)

            return result


async def run_watch(
    packages: list[str],
    enable_triage: bool = False,
    store: VajraStore | None = None,
) -> WatchResult:
    """Run drift detection on a list of packages."""
    watch = WatchResult(
        timestamp=datetime.now(timezone.utc).isoformat(),
        packages_scanned=0,
    )

    semaphore = asyncio.Semaphore(_SEMAPHORE_LIMIT)

    async with httpx.AsyncClient(timeout=60.0) as client:
        total = len(packages)
        for i, package in enumerate(packages, 1):
            console.print(
                f"[cyan][{i}/{total}][/cyan] Auditing [bold]{package}[/bold]..."
            )
            try:
                result = await audit_single_package(
                    client, package, semaphore, store, enable_triage
                )
            except Exception as e:
                console.print(f"[red]  Error auditing {package}: {e}[/red]")
                continue

            watch.packages_scanned += 1
            if result:
                watch.audits.append(result)
                if result.verdict != Verdict.CLEAN:
                    watch.drift_found += 1
                    verdict_style = (
                        "red" if result.verdict == Verdict.CRITICAL else "yellow"
                    )
                    console.print(
                        f"  [{verdict_style}]{result.verdict.value}[/{verdict_style}] "
                        f"{package}=={result.version} "
                        f"({result.critical_count} critical, {result.warning_count} warnings)"
                    )
                else:
                    console.print(f"  [green]CLEAN[/green] {package}=={result.version}")

    return watch
