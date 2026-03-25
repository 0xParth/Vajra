"""GitHub API client — resolve repos, download tag archives, handle rate limits."""

from __future__ import annotations

import asyncio
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, DownloadColumn

from vajra.config import GITHUB_API_BASE, GITHUB_ARCHIVE_BASE, github_token

console = Console(stderr=True)


def _auth_headers() -> dict[str, str]:
    token = github_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


async def check_rate_limit(client: httpx.AsyncClient) -> None:
    """Warn and throttle when approaching GitHub API rate limits."""
    resp = await client.get(
        f"{GITHUB_API_BASE}/rate_limit", headers=_auth_headers()
    )
    if resp.status_code != 200:
        return
    data = resp.json()
    remaining = data.get("resources", {}).get("core", {}).get("remaining", -1)
    if remaining == -1:
        return
    if remaining < 5:
        reset_at = data["resources"]["core"]["reset"]
        console.print(
            f"[yellow]GitHub API rate limit nearly exhausted "
            f"({remaining} remaining). Resets at epoch {reset_at}.[/yellow]"
        )
        console.print(
            "[dim]Tip: set GITHUB_TOKEN env var for 5 000 requests/hour.[/dim]"
        )
        if remaining == 0:
            import time
            wait = max(0, reset_at - int(time.time())) + 1
            console.print(f"[yellow]Sleeping {wait}s until reset...[/yellow]")
            await asyncio.sleep(wait)


async def _handle_rate_limit(resp: httpx.Response) -> None:
    remaining = int(resp.headers.get("x-ratelimit-remaining", "999"))
    if remaining < 10:
        console.print(
            f"[yellow]GitHub rate limit: {remaining} requests remaining.[/yellow]"
        )
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        reset_ts = int(resp.headers.get("x-ratelimit-reset", "0"))
        if reset_ts:
            import time
            wait = max(0, reset_ts - int(time.time())) + 2
            console.print(
                f"[yellow]Rate limited. Sleeping {wait}s...[/yellow]"
            )
            await asyncio.sleep(wait)


_TAG_FORMATS = [
    "v{version}",
    "{version}",
    "{package}-{version}",
    "{package}-v{version}",
    "release-{version}",
]


async def find_matching_tag(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    package: str,
    version: str,
) -> str | None:
    """Try common tag formats and return the first that exists, or None."""
    headers = _auth_headers()
    for fmt in _TAG_FORMATS:
        tag = fmt.format(version=version, package=package)
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/ref/tags/{tag}"
        resp = await client.get(url, headers=headers)
        await _handle_rate_limit(resp)
        if resp.status_code == 200:
            return tag
    return None


async def download_tag_archive(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    tag: str,
    dest: Path,
    show_progress: bool = True,
) -> Path:
    """Download and extract a GitHub tag archive into *dest*.

    Returns the path to the extracted top-level directory.
    """
    url = f"{GITHUB_ARCHIVE_BASE}/{owner}/{repo}/archive/refs/tags/{tag}.tar.gz"
    headers = _auth_headers()

    async with client.stream("GET", url, headers=headers, follow_redirects=True) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        archive_path = dest / f"{repo}-{tag}.tar.gz"

        if show_progress and total:
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                DownloadColumn(),
            ) as progress:
                task = progress.add_task("Downloading GitHub source", total=total)
                with open(archive_path, "wb") as f:
                    async for chunk in resp.aiter_bytes(8192):
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))
        else:
            with open(archive_path, "wb") as f:
                async for chunk in resp.aiter_bytes(8192):
                    f.write(chunk)

    extract_dir = dest / "gh_extracted"
    extract_dir.mkdir(exist_ok=True)

    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as tf:
            tf.extractall(extract_dir, filter="data")
    elif zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(extract_dir)
    else:
        raise ValueError(f"Unknown archive format: {archive_path.name}")

    children = list(extract_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return extract_dir


async def get_recent_releases(
    client: httpx.AsyncClient, owner: str, repo: str, count: int = 5
) -> list[dict[str, Any]]:
    """Fetch the latest *count* releases from GitHub API."""
    headers = _auth_headers()
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/releases"
    resp = await client.get(
        url, headers=headers, params={"per_page": count}
    )
    await _handle_rate_limit(resp)
    if resp.status_code != 200:
        return []
    return resp.json()[:count]
