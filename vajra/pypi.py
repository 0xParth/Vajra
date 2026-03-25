"""PyPI JSON API client — fetch metadata, download sdists, extract GitHub URLs."""

from __future__ import annotations

import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx
from rich.progress import Progress, SpinnerColumn, BarColumn, DownloadColumn

from vajra.config import PYPI_API_BASE

_GITHUB_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/#?]+)"
)


async def fetch_metadata(
    client: httpx.AsyncClient, package: str, version: str | None = None
) -> dict[str, Any]:
    """Fetch package metadata from PyPI JSON API.

    Returns the full JSON response.  Raises on HTTP errors.
    """
    if version:
        url = f"{PYPI_API_BASE}/{package}/{version}/json"
    else:
        url = f"{PYPI_API_BASE}/{package}/json"

    resp = await client.get(url, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


def find_sdist_url(metadata: dict[str, Any], version: str) -> str | None:
    """Extract the source distribution (.tar.gz or .zip) URL from metadata."""
    urls = metadata.get("urls", [])
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            return entry["url"]

    releases = metadata.get("releases", {})
    for entry in releases.get(version, []):
        if entry.get("packagetype") == "sdist":
            return entry["url"]

    return None


def extract_github_repo(metadata: dict[str, Any]) -> tuple[str, str] | None:
    """Try to find owner/repo from PyPI project URLs.

    Checks project_urls, home_page, and description for GitHub links.
    """
    info = metadata.get("info", {})

    project_urls: dict[str, str] = info.get("project_urls") or {}
    for key in ("Source", "Repository", "Source Code", "GitHub", "Homepage", "Code"):
        url = project_urls.get(key, "")
        m = _GITHUB_RE.match(url)
        if m:
            return m.group("owner"), _clean_repo(m.group("repo"))

    for key in project_urls:
        url = project_urls[key]
        m = _GITHUB_RE.match(url)
        if m:
            return m.group("owner"), _clean_repo(m.group("repo"))

    home_page = info.get("home_page") or ""
    m = _GITHUB_RE.match(home_page)
    if m:
        return m.group("owner"), _clean_repo(m.group("repo"))

    return None


async def download_and_extract(
    client: httpx.AsyncClient,
    url: str,
    dest: Path,
    show_progress: bool = True,
) -> Path:
    """Stream-download an archive and extract it into *dest*.

    Returns the path to the single top-level directory inside *dest*.
    """
    async with client.stream("GET", url, follow_redirects=True) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        archive_path = dest / url.rsplit("/", 1)[-1]

        if show_progress and total:
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                DownloadColumn(),
            ) as progress:
                task = progress.add_task("Downloading sdist", total=total)
                with open(archive_path, "wb") as f:
                    async for chunk in resp.aiter_bytes(8192):
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))
        else:
            with open(archive_path, "wb") as f:
                async for chunk in resp.aiter_bytes(8192):
                    f.write(chunk)

    extract_dir = dest / "extracted"
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


async def get_all_versions(
    client: httpx.AsyncClient, package: str
) -> list[str]:
    """Return all available versions sorted by upload time (newest first)."""
    metadata = await fetch_metadata(client, package)
    releases: dict[str, list[dict]] = metadata.get("releases", {})

    version_dates: list[tuple[str, str]] = []
    for ver, files in releases.items():
        if not files:
            continue
        upload_time = files[0].get("upload_time_iso_8601") or files[0].get(
            "upload_time", ""
        )
        version_dates.append((ver, upload_time))

    version_dates.sort(key=lambda x: x[1], reverse=True)
    return [v for v, _ in version_dates]


def _clean_repo(repo: str) -> str:
    """Strip trailing .git or path fragments from a repo name."""
    repo = repo.rstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if "/" in repo:
        repo = repo.split("/")[0]
    return repo
