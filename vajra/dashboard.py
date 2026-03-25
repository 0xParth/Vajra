"""Static dashboard generator — HTML, JSON feed, and RSS/Atom feed."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from jinja2 import Environment, FileSystemLoader
from rich.console import Console

from vajra.config import DEFAULT_DASHBOARD_DIR
from vajra.store import VajraStore

console = Console(stderr=True)


def generate_dashboard(
    store: VajraStore,
    output_dir: Path | None = None,
) -> Path:
    """Generate a static dashboard site from scan data.

    Returns the output directory path.
    """
    out = output_dir or DEFAULT_DASHBOARD_DIR
    out.mkdir(parents=True, exist_ok=True)

    stats = store.get_stats()
    flagged = store.get_flagged_scans()
    all_scans = store.get_all_scans()
    recent_clean = [s for s in all_scans if s["verdict"] == "CLEAN"][:20]

    triage_entries = []
    file_drifts_map: dict[int, list[dict]] = {}
    triage_map: dict[int, list[dict]] = {}

    for s in flagged:
        sid = s["id"]
        file_drifts_map[sid] = store.get_file_drifts(sid)
        tvs = store.get_triage_verdicts(sid)
        triage_map[sid] = tvs
        for tv in tvs:
            entry = dict(tv)
            entry["package"] = f"{s['package']}=={s['version']}"
            triage_entries.append(entry)

    mass_drift_ids: set[int] = set()
    for sid, drifts in file_drifts_map.items():
        if any(d.get("detail", "").startswith("[mass-drift]") for d in drifts):
            mass_drift_ids.add(sid)

    threats = [s for s in flagged if s["id"] not in mass_drift_ids]
    noise = [s for s in flagged if s["id"] in mass_drift_ids]

    reasons_map: dict[int, list[str]] = {}
    for s in flagged:
        sid = s["id"]
        drifts = file_drifts_map.get(sid, [])
        reasons: list[str] = []
        for d in drifts:
            if d.get("severity") != "CRITICAL":
                continue
            path = d.get("path", "")
            dtype = d.get("drift_type", "")
            if dtype == "PYPI_ONLY":
                reasons.append(f"{path} injected (PyPI-only)")
            elif dtype == "CONTENT_MISMATCH":
                reasons.append(f"{path} modified")
            elif dtype == "NO_GITHUB_TAG":
                reasons.append("No GitHub tag for this version")
            else:
                reasons.append(f"{path} ({dtype})")
        if not reasons and s.get("critical", 0) == 0:
            warning_count = len([
                d for d in drifts
                if d.get("severity") == "WARNING"
                and not d.get("detail", "").startswith("[mass-drift]")
            ])
            if warning_count:
                reasons.append(f"{warning_count} files differ from GitHub")
        reasons_map[sid] = reasons[:5]

    _generate_html(
        out, stats, threats, noise, triage_entries, recent_clean,
        file_drifts_map, triage_map, mass_drift_ids, reasons_map,
    )
    _generate_json_feed(out, store)
    _generate_rss_feed(out, stats, flagged)

    console.print(f"[green]Dashboard generated at: {out}[/green]")
    return out


def _generate_html(
    out: Path,
    stats: dict,
    threats: list[dict],
    noise: list[dict],
    triage_entries: list[dict],
    recent_clean: list[dict],
    file_drifts_map: dict[int, list[dict]] | None = None,
    triage_map: dict[int, list[dict]] | None = None,
    mass_drift_ids: set[int] | None = None,
    reasons_map: dict[int, list[str]] | None = None,
) -> None:
    templates_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    template = env.get_template("dashboard.html")

    html = template.render(
        stats=stats,
        last_scan=stats.get("last_scan"),
        threats=threats,
        noise=noise,
        triage_entries=triage_entries,
        recent_clean=recent_clean,
        file_drifts_map=file_drifts_map or {},
        triage_map=triage_map or {},
        mass_drift_ids=mass_drift_ids or set(),
        reasons_map=reasons_map or {},
    )
    (out / "index.html").write_text(html)


def _generate_json_feed(out: Path, store: VajraStore) -> None:
    data = store.export_json()
    stats = store.get_stats()
    feed = {
        "generator": "vajra",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "findings": data,
    }
    (out / "feed.json").write_text(json.dumps(feed, indent=2, default=str))


def _generate_rss_feed(
    out: Path, stats: dict, flagged: list[dict]
) -> None:
    rss = Element("rss", version="2.0")
    channel = SubElement(rss, "channel")
    SubElement(channel, "title").text = "Vajra — Supply Chain Drift Monitor"
    SubElement(channel, "description").text = (
        "Automated source-to-artifact drift detection for PyPI packages"
    )
    SubElement(channel, "lastBuildDate").text = datetime.now(
        timezone.utc
    ).strftime("%a, %d %b %Y %H:%M:%S +0000")

    for s in flagged[:50]:
        item = SubElement(channel, "item")
        SubElement(item, "title").text = (
            f"[{s['verdict']}] {s['package']}=={s['version']}"
        )
        SubElement(item, "description").text = (
            f"Drift detected: {s['critical']} critical, "
            f"{s['warnings']} warnings. "
            f"GitHub: {s.get('github_repo', 'unknown')}"
        )
        SubElement(item, "pubDate").text = s.get("timestamp", "")
        if s.get("github_repo"):
            SubElement(item, "link").text = (
                f"https://github.com/{s['github_repo']}"
            )

    xml_bytes = tostring(rss, encoding="unicode", xml_declaration=True)
    (out / "feed.xml").write_text(xml_bytes)
