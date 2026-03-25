"""The Vajra Audit — file tree diff, content hash comparison, metadata checks."""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

from vajra.config import (
    is_always_critical,
    is_github_only_expected,
    is_high_risk,
    is_noise,
    is_vendored,
)
from vajra.models import (
    AuditResult,
    DriftType,
    FileDrift,
    Severity,
    Verdict,
)


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_tree(root: Path) -> dict[str, str]:
    """Walk *root* and return ``{relative_posix_path: sha256}``."""
    tree: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        tree[rel] = compute_sha256(path)
    return tree


_MASS_DRIFT_THRESHOLD = 15


def _classify(path: str, drift_type: DriftType) -> Severity:
    """Assign severity based on file classification and drift type."""
    if drift_type == DriftType.MATCH:
        return Severity.OK

    if drift_type == DriftType.PYPI_ONLY:
        if is_noise(path):
            return Severity.INFO
        if is_vendored(path):
            return Severity.INFO
        if is_high_risk(path):
            return Severity.CRITICAL
        return Severity.WARNING

    if drift_type == DriftType.GITHUB_ONLY:
        if is_github_only_expected(path):
            return Severity.INFO
        return Severity.WARNING

    if drift_type == DriftType.CONTENT_MISMATCH:
        if is_noise(path):
            return Severity.INFO
        if is_high_risk(path):
            return Severity.CRITICAL
        return Severity.WARNING

    return Severity.WARNING


def _apply_mass_drift_heuristic(files: list[FileDrift]) -> None:
    """Downgrade non-high-risk CRITICALs and tag WARNINGs when drift is
    too widespread.

    Real supply chain attacks are surgical (1-5 files). When dozens of
    files drift it is almost always a packaging / vendoring mismatch.
    High-risk files (.pth, .so, setup.py, __init__.py) keep their
    severity regardless.
    """
    actionable = [
        f for f in files
        if f.severity in (Severity.WARNING, Severity.CRITICAL)
    ]
    if len(actionable) <= _MASS_DRIFT_THRESHOLD:
        return

    for f in files:
        if f.severity not in (Severity.WARNING, Severity.CRITICAL):
            continue
        if is_always_critical(f.path):
            continue
        if f.severity == Severity.CRITICAL:
            f.severity = Severity.WARNING
        if not f.detail.startswith("[mass-drift]"):
            f.detail = f"[mass-drift] {f.detail}"


def run_audit(
    pypi_tree: dict[str, str],
    github_tree: dict[str, str],
    package: str,
    version: str,
    github_repo: str = "",
    github_tag: str = "",
    github_tag_exists: bool = True,
) -> AuditResult:
    """Compare PyPI and GitHub file trees and produce an ``AuditResult``."""
    files: list[FileDrift] = []

    pypi_paths = set(pypi_tree.keys())
    github_paths = set(github_tree.keys())

    common = pypi_paths & github_paths
    pypi_only = pypi_paths - github_paths
    github_only = github_paths - pypi_paths

    for path in sorted(common):
        if pypi_tree[path] == github_tree[path]:
            files.append(
                FileDrift(
                    path=path,
                    drift_type=DriftType.MATCH,
                    severity=Severity.OK,
                    pypi_sha256=pypi_tree[path],
                    github_sha256=github_tree[path],
                )
            )
        else:
            dt = DriftType.CONTENT_MISMATCH
            files.append(
                FileDrift(
                    path=path,
                    drift_type=dt,
                    severity=_classify(path, dt),
                    pypi_sha256=pypi_tree[path],
                    github_sha256=github_tree[path],
                    detail="SHA256 mismatch between PyPI and GitHub",
                )
            )

    for path in sorted(pypi_only):
        dt = DriftType.PYPI_ONLY
        sev = _classify(path, dt)
        detail = "File exists in PyPI sdist but NOT in GitHub source"
        if sev == Severity.CRITICAL:
            detail += " — HIGH RISK: executable/importable code"
        files.append(
            FileDrift(
                path=path,
                drift_type=dt,
                severity=sev,
                pypi_sha256=pypi_tree[path],
                detail=detail,
            )
        )

    for path in sorted(github_only):
        dt = DriftType.GITHUB_ONLY
        files.append(
            FileDrift(
                path=path,
                drift_type=dt,
                severity=_classify(path, dt),
                github_sha256=github_tree[path],
                detail="File exists in GitHub but not in PyPI sdist",
            )
        )

    if not github_tag_exists:
        files.insert(
            0,
            FileDrift(
                path="<metadata>",
                drift_type=DriftType.NO_GITHUB_TAG,
                severity=Severity.CRITICAL,
                detail=f"No GitHub tag/release found for version {version}",
            ),
        )

    _apply_mass_drift_heuristic(files)

    verdict = _compute_verdict(files, github_tag_exists)

    return AuditResult(
        package=package,
        version=version,
        verdict=verdict,
        github_repo=github_repo,
        github_tag=github_tag,
        github_tag_exists=github_tag_exists,
        files=files,
        pypi_file_count=len(pypi_paths),
        github_file_count=len(github_paths),
    )


def content_diff(
    pypi_dir: Path, github_dir: Path, file_drift: FileDrift
) -> str:
    """Produce a unified diff or full content for a drifted file.

    For content mismatches: returns a unified diff.
    For pypi-only files: returns the full file content.
    """
    pypi_path = pypi_dir / file_drift.path
    github_path = github_dir / file_drift.path

    if file_drift.drift_type == DriftType.PYPI_ONLY:
        if pypi_path.exists():
            try:
                return pypi_path.read_text(errors="replace")
            except Exception:
                return "(binary or unreadable file)"
        return "(file not found)"

    if file_drift.drift_type == DriftType.CONTENT_MISMATCH:
        try:
            pypi_lines = pypi_path.read_text(errors="replace").splitlines(keepends=True)
            github_lines = github_path.read_text(errors="replace").splitlines(keepends=True)
        except Exception:
            return "(binary or unreadable file)"

        diff = difflib.unified_diff(
            github_lines,
            pypi_lines,
            fromfile=f"github/{file_drift.path}",
            tofile=f"pypi/{file_drift.path}",
        )
        return "".join(diff) or "(files differ but diff is empty — possibly binary)"

    return ""


def _compute_verdict(files: list[FileDrift], tag_exists: bool) -> Verdict:
    if not tag_exists:
        return Verdict.CRITICAL
    if any(f.severity == Severity.CRITICAL for f in files):
        return Verdict.CRITICAL
    if any(f.severity == Severity.WARNING for f in files):
        return Verdict.WARN
    return Verdict.CLEAN
