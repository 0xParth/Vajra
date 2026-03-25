"""SQLite persistence for scan results and triage verdicts."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from vajra.config import DEFAULT_DB_PATH
from vajra.models import (
    AIVerdict,
    AuditResult,
    DriftType,
    FileDrift,
    Severity,
    TriageVerdict,
    Verdict,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    package     TEXT NOT NULL,
    version     TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    critical    INTEGER NOT NULL DEFAULT 0,
    warnings    INTEGER NOT NULL DEFAULT 0,
    ok          INTEGER NOT NULL DEFAULT 0,
    pypi_files  INTEGER NOT NULL DEFAULT 0,
    gh_files    INTEGER NOT NULL DEFAULT 0,
    github_repo TEXT NOT NULL DEFAULT '',
    github_tag  TEXT NOT NULL DEFAULT '',
    tag_exists  INTEGER NOT NULL DEFAULT 1,
    triage_run  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(package, version, timestamp)
);

CREATE TABLE IF NOT EXISTS file_drifts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    path        TEXT NOT NULL,
    drift_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    pypi_sha256 TEXT,
    gh_sha256   TEXT,
    detail      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS triage_verdicts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    file_path       TEXT NOT NULL,
    ai_verdict      TEXT NOT NULL,
    confidence      INTEGER NOT NULL DEFAULT 0,
    threat_category TEXT NOT NULL DEFAULT '',
    explanation     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scans_pkg ON scans(package, version);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_drifts_scan ON file_drifts(scan_id);
CREATE INDEX IF NOT EXISTS idx_triage_scan ON triage_verdicts(scan_id);
"""


class VajraStore:
    def __init__(self, db_path: Path | str | None = None):
        self._path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> VajraStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def save_scan(
        self,
        result: AuditResult,
        triage_verdicts: list[TriageVerdict] | None = None,
    ) -> int:
        ts = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            """INSERT INTO scans
               (package, version, timestamp, verdict, critical, warnings,
                ok, pypi_files, gh_files, github_repo, github_tag,
                tag_exists, triage_run)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.package,
                result.version,
                ts,
                result.verdict.value,
                result.critical_count,
                result.warning_count,
                result.ok_count,
                result.pypi_file_count,
                result.github_file_count,
                result.github_repo,
                result.github_tag,
                int(result.github_tag_exists),
                int(bool(triage_verdicts)),
            ),
        )
        scan_id = cur.lastrowid

        non_ok = [f for f in result.files if f.severity != Severity.OK]
        for f in non_ok:
            self._conn.execute(
                """INSERT INTO file_drifts
                   (scan_id, path, drift_type, severity, pypi_sha256, gh_sha256, detail)
                   VALUES (?,?,?,?,?,?,?)""",
                (scan_id, f.path, f.drift_type.value, f.severity.value,
                 f.pypi_sha256, f.github_sha256, f.detail),
            )

        if triage_verdicts:
            for tv in triage_verdicts:
                self._conn.execute(
                    """INSERT INTO triage_verdicts
                       (scan_id, file_path, ai_verdict, confidence,
                        threat_category, explanation)
                       VALUES (?,?,?,?,?,?)""",
                    (scan_id, tv.file_path, tv.ai_verdict.value,
                     tv.confidence, tv.threat_category, tv.explanation),
                )

        self._conn.commit()
        return scan_id

    def has_scan(self, package: str, version: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM scans WHERE package=? AND version=? LIMIT 1",
            (package, version),
        ).fetchone()
        return row is not None

    def get_latest_scan(self, package: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM scans WHERE package=? ORDER BY timestamp DESC LIMIT 1",
            (package,),
        ).fetchone()
        return dict(row) if row else None

    def get_all_scans(self, limit: int = 500) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_flagged_scans(self, limit: int = 200) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scans WHERE verdict != 'CLEAN' ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_file_drifts(self, scan_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM file_drifts WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_triage_verdicts(self, scan_id: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM triage_verdicts WHERE scan_id=?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        clean = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict='CLEAN'"
        ).fetchone()[0]
        warn = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict='WARN'"
        ).fetchone()[0]
        critical = self._conn.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict='CRITICAL'"
        ).fetchone()[0]
        threats = self._conn.execute(
            "SELECT COUNT(*) FROM triage_verdicts WHERE ai_verdict='malicious'"
        ).fetchone()[0]
        latest = self._conn.execute(
            "SELECT timestamp FROM scans ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        return {
            "total_scans": total,
            "clean": clean,
            "warnings": warn,
            "critical": critical,
            "confirmed_threats": threats,
            "last_scan": latest[0] if latest else None,
        }

    def export_json(self) -> list[dict]:
        scans = self.get_flagged_scans()
        result = []
        for s in scans:
            entry = dict(s)
            entry["file_drifts"] = self.get_file_drifts(s["id"])
            entry["triage_verdicts"] = self.get_triage_verdicts(s["id"])
            result.append(entry)
        return result
