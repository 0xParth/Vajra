"""Rich-based CLI reporter — color-coded output for audit results."""

from __future__ import annotations

import json as _json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vajra.models import (
    AIVerdict,
    AuditResult,
    DriftType,
    Severity,
    TriageVerdict,
    Verdict,
    VersionScanResult,
)

console = Console()

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.WARNING: "yellow",
    Severity.INFO: "dim",
    Severity.OK: "green",
}

_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.CRITICAL: "bold red",
    Verdict.WARN: "yellow",
    Verdict.CLEAN: "bold green",
}

_DRIFT_LABELS: dict[DriftType, str] = {
    DriftType.MATCH: "Match",
    DriftType.CONTENT_MISMATCH: "Content Mismatch",
    DriftType.PYPI_ONLY: "PyPI Only",
    DriftType.GITHUB_ONLY: "GitHub Only",
    DriftType.NO_GITHUB_TAG: "No GitHub Tag",
}


def print_audit(result: AuditResult, verbose: bool = False) -> None:
    """Print a full audit report to the console."""
    _print_summary_panel(result)
    _print_file_table(result, verbose)
    _print_verdict_footer(result)


def print_audit_json(result: AuditResult) -> None:
    """Print audit result as machine-readable JSON."""
    data = _audit_to_dict(result)
    console.print_json(_json.dumps(data))


def print_version_scan(scan: VersionScanResult) -> None:
    """Print a multi-version recon scan report."""
    console.print()
    console.print(
        Panel(
            f"[bold]Recon Scan: {scan.package}[/bold]\n"
            f"Versions scanned: {', '.join(scan.versions_scanned)}",
            title="Vajra Recon Mode",
            border_style="cyan",
        )
    )

    if scan.maintainer_changed:
        console.print(
            "\n[bold red]ALERT: Maintainer changed between versions![/bold red]"
        )
        table = Table(title="Maintainer History")
        table.add_column("Version", style="cyan")
        table.add_column("Author")
        table.add_column("Email")
        table.add_column("Maintainer")
        for mi in scan.maintainer_history:
            table.add_row(mi.version, mi.author, mi.author_email, mi.maintainer)
        console.print(table)

    if scan.file_count_anomalies:
        console.print("\n[bold yellow]File count anomalies detected:[/bold yellow]")
        for note in scan.file_count_anomalies:
            console.print(f"  [yellow]• {note}[/yellow]")

    console.print()
    overview = Table(title="Version Overview")
    overview.add_column("Version", style="cyan")
    overview.add_column("Verdict")
    overview.add_column("Critical", justify="right")
    overview.add_column("Warnings", justify="right")
    overview.add_column("OK", justify="right")
    overview.add_column("PyPI Files", justify="right")
    overview.add_column("GH Files", justify="right")

    for audit in scan.audits:
        verdict_text = Text(audit.verdict.value, style=_VERDICT_STYLES[audit.verdict])
        overview.add_row(
            audit.version,
            verdict_text,
            str(audit.critical_count),
            str(audit.warning_count),
            str(audit.ok_count),
            str(audit.pypi_file_count),
            str(audit.github_file_count),
        )

    console.print(overview)

    for audit in scan.audits:
        if audit.verdict != Verdict.CLEAN:
            console.print(f"\n[bold]--- Details for v{audit.version} ---[/bold]")
            _print_file_table(audit, verbose=False)


def _print_summary_panel(result: AuditResult) -> None:
    repo_info = f"GitHub: {result.github_repo}" if result.github_repo else "GitHub: [dim]not resolved[/dim]"
    tag_info = f"Tag: {result.github_tag}" if result.github_tag else "Tag: [dim]none found[/dim]"

    content = (
        f"[bold]{result.package}[/bold] v{result.version}\n"
        f"{repo_info}  |  {tag_info}\n"
        f"PyPI files: {result.pypi_file_count}  |  "
        f"GitHub files: {result.github_file_count}"
    )

    console.print()
    console.print(Panel(content, title="Vajra Audit", border_style="cyan"))


def _print_file_table(result: AuditResult, verbose: bool = False) -> None:
    table = Table(show_lines=False, pad_edge=True, expand=True)
    table.add_column("Status", width=10)
    table.add_column("File", ratio=3)
    table.add_column("Type", width=18)
    table.add_column("Detail", ratio=2)

    for f in result.files:
        if not verbose and f.severity == Severity.OK:
            continue
        if not verbose and f.severity == Severity.INFO:
            continue

        style = _SEVERITY_STYLES[f.severity]
        status_text = Text(f.severity.value, style=style)
        drift_label = _DRIFT_LABELS.get(f.drift_type, f.drift_type.value)
        detail = f.detail or ""

        table.add_row(status_text, f.path, drift_label, detail)

    if verbose:
        ok_count = result.ok_count
        info_count = sum(1 for f in result.files if f.severity == Severity.INFO)
        table.caption = f"{ok_count} matched, {info_count} noise/expected"
    else:
        hidden = sum(
            1
            for f in result.files
            if f.severity in (Severity.OK, Severity.INFO)
        )
        if hidden:
            table.caption = f"{hidden} clean/noise files hidden (use --verbose to show)"

    console.print(table)


def _print_verdict_footer(result: AuditResult) -> None:
    style = _VERDICT_STYLES[result.verdict]
    icon = {
        Verdict.CLEAN: "PASS",
        Verdict.WARN: "WARN",
        Verdict.CRITICAL: "FAIL",
    }[result.verdict]

    summary_parts = []
    if result.critical_count:
        summary_parts.append(f"[red]{result.critical_count} critical[/red]")
    if result.warning_count:
        summary_parts.append(f"[yellow]{result.warning_count} warnings[/yellow]")
    summary_parts.append(f"[green]{result.ok_count} clean[/green]")

    console.print()
    console.print(
        Panel(
            f"[{style}]{icon}: {result.verdict.value}[/{style}]  "
            f"({', '.join(summary_parts)})",
            border_style=style.split()[-1],
        )
    )
    console.print()


def print_triage_verdicts(verdicts: list[TriageVerdict]) -> None:
    """Print AI triage results as a Rich table."""
    if not verdicts:
        return

    console.print()
    console.print(Panel("[bold]AI Triage Results[/bold]", border_style="magenta"))

    table = Table(show_lines=False, pad_edge=True, expand=True)
    table.add_column("AI Verdict", width=12)
    table.add_column("File", ratio=2)
    table.add_column("Confidence", width=12, justify="right")
    table.add_column("Category", width=18)
    table.add_column("Explanation", ratio=3)

    _verdict_styles = {
        AIVerdict.MALICIOUS: "bold red",
        AIVerdict.SUSPICIOUS: "yellow",
        AIVerdict.BENIGN: "green",
        AIVerdict.ERROR: "dim",
    }

    for tv in verdicts:
        style = _verdict_styles.get(tv.ai_verdict, "dim")
        verdict_text = Text(tv.ai_verdict.value.upper(), style=style)
        conf = f"{tv.confidence}%"
        table.add_row(
            verdict_text, tv.file_path, conf, tv.threat_category, tv.explanation
        )

    console.print(table)

    malicious = sum(1 for v in verdicts if v.ai_verdict == AIVerdict.MALICIOUS)
    suspicious = sum(1 for v in verdicts if v.ai_verdict == AIVerdict.SUSPICIOUS)
    benign = sum(1 for v in verdicts if v.ai_verdict == AIVerdict.BENIGN)

    parts = []
    if malicious:
        parts.append(f"[bold red]{malicious} MALICIOUS[/bold red]")
    if suspicious:
        parts.append(f"[yellow]{suspicious} suspicious[/yellow]")
    if benign:
        parts.append(f"[green]{benign} benign[/green]")

    if parts:
        console.print(f"  AI summary: {', '.join(parts)}")
    console.print()


def _audit_to_dict(result: AuditResult) -> dict[str, Any]:
    return {
        "package": result.package,
        "version": result.version,
        "verdict": result.verdict.value,
        "github_repo": result.github_repo,
        "github_tag": result.github_tag,
        "github_tag_exists": result.github_tag_exists,
        "pypi_file_count": result.pypi_file_count,
        "github_file_count": result.github_file_count,
        "critical": result.critical_count,
        "warnings": result.warning_count,
        "ok": result.ok_count,
        "files": [
            {
                "path": f.path,
                "drift_type": f.drift_type.value,
                "severity": f.severity.value,
                "pypi_sha256": f.pypi_sha256,
                "github_sha256": f.github_sha256,
                "detail": f.detail,
            }
            for f in result.files
        ],
    }
