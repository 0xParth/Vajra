"""Constants, file classification patterns, and noise filters."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath

PYPI_API_BASE = "https://pypi.org/pypi"
GITHUB_API_BASE = "https://api.github.com"
GITHUB_ARCHIVE_BASE = "https://github.com"

HIGH_RISK_GLOBS: list[str] = [
    "*.pth",
    "*.so",
    "*.dll",
    "*.dylib",
    "*.exe",
    "*.bat",
    "*.cmd",
    "*.sh",
]

HIGH_RISK_NAMES: set[str] = {
    "setup.py",
    "MANIFEST.in",
    "conftest.py",
}

HIGH_RISK_SUFFIXES: set[str] = {
    "__init__.py",
}

NOISE_GLOBS: list[str] = [
    "PKG-INFO",
    "SOURCES.txt",
    "*.egg-info/*",
    "*.egg-info",
    "*.dist-info/*",
    "*.dist-info",
    "dependency_links.txt",
    "top_level.txt",
    "requires.txt",
    "not-zip-safe",
    "zip-safe",
    "setup.cfg",
]

GITHUB_ONLY_GLOBS: list[str] = [
    # VCS / CI config
    ".gitignore",
    ".gitattributes",
    ".github/*",
    ".github/**/*",
    ".circleci/*",
    ".circleci/**/*",
    ".travis.yml",
    "appveyor.yml",
    "codecov.yml",
    ".pre-commit-config.yaml",
    # Linters / tools
    ".flake8",
    ".mypy.ini",
    ".pylintrc",
    ".coveragerc",
    ".editorconfig",
    ".readthedocs.yml",
    ".readthedocs.yaml",
    "tox.ini",
    "noxfile.py",
    "Makefile",
    # Docs and assets (common dirs not shipped in sdist)
    "docs/*",
    "docs/**/*",
    "doc/*",
    "doc/**/*",
    "ext/*",
    "ext/**/*",
    "examples/*",
    "examples/**/*",
    "benchmarks/*",
    "benchmarks/**/*",
    # Project metadata files
    "LICENSE",
    "LICENSE.*",
    "CONTRIBUTING.md",
    "CONTRIBUTING.rst",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "CHANGELOG.rst",
    "CHANGES.rst",
    "CHANGES.md",
    "AUTHORS",
    "AUTHORS.md",
    "AUTHORS.rst",
]

FILE_COUNT_DELTA_THRESHOLD = 0.20  # 20% change flags a warning in recon mode

DEFAULT_VERSION_SCAN_COUNT = 5

TOP_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/"
    "top-pypi-packages-30-days.min.json"
)
DEFAULT_WATCH_COUNT = 100

DEFAULT_DB_PATH = Path("~/.vajra/vajra.db").expanduser()
DEFAULT_DASHBOARD_DIR = Path("~/.vajra/public").expanduser()

TRIAGE_MODEL = os.environ.get("VAJRA_TRIAGE_MODEL", "claude-sonnet-4-20250514")
MAX_DIFF_CHARS = 12_000  # truncate diffs sent to AI to control token cost


def github_token() -> str | None:
    """Read optional GitHub token from environment."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def anthropic_api_key() -> str | None:
    """Read Anthropic API key from environment."""
    return os.environ.get("ANTHROPIC_API_KEY")


def _matches_any(path: str, patterns: list[str]) -> bool:
    name = PurePosixPath(path).name
    for pat in patterns:
        if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def is_high_risk(path: str) -> bool:
    name = PurePosixPath(path).name
    if name in HIGH_RISK_NAMES:
        return True
    if name.endswith("__init__.py"):
        return True
    return _matches_any(path, HIGH_RISK_GLOBS)


def is_noise(path: str) -> bool:
    return _matches_any(path, NOISE_GLOBS)


def is_github_only_expected(path: str) -> bool:
    return _matches_any(path, GITHUB_ONLY_GLOBS)
