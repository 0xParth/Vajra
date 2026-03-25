"""Tests for the SQLite store."""

from __future__ import annotations

import tempfile
from pathlib import Path

from vajra.models import (
    AIVerdict,
    AuditResult,
    DriftType,
    FileDrift,
    Severity,
    TriageVerdict,
    Verdict,
)
from vajra.store import VajraStore


def _make_result(verdict: Verdict = Verdict.CRITICAL) -> AuditResult:
    return AuditResult(
        package="testpkg",
        version="1.0.0",
        verdict=verdict,
        github_repo="owner/repo",
        github_tag="v1.0.0",
        github_tag_exists=True,
        files=[
            FileDrift(
                path="setup.py",
                drift_type=DriftType.CONTENT_MISMATCH,
                severity=Severity.CRITICAL,
                pypi_sha256="aaa",
                github_sha256="bbb",
                detail="SHA256 mismatch",
            ),
            FileDrift(
                path="pkg/__init__.py",
                drift_type=DriftType.MATCH,
                severity=Severity.OK,
                pypi_sha256="ccc",
                github_sha256="ccc",
            ),
        ],
        pypi_file_count=5,
        github_file_count=4,
    )


def _make_triage() -> list[TriageVerdict]:
    return [
        TriageVerdict(
            file_path="setup.py",
            ai_verdict=AIVerdict.MALICIOUS,
            confidence=95,
            threat_category="backdoor",
            explanation="Injected subprocess call with base64 payload.",
        )
    ]


class TestVajraStore:
    def _store(self) -> VajraStore:
        tmp = tempfile.mktemp(suffix=".db")
        return VajraStore(tmp)

    def test_save_and_retrieve(self):
        with self._store() as store:
            result = _make_result()
            scan_id = store.save_scan(result)
            assert scan_id > 0

            latest = store.get_latest_scan("testpkg")
            assert latest is not None
            assert latest["package"] == "testpkg"
            assert latest["verdict"] == "CRITICAL"

    def test_has_scan(self):
        with self._store() as store:
            assert not store.has_scan("testpkg", "1.0.0")
            store.save_scan(_make_result())
            assert store.has_scan("testpkg", "1.0.0")

    def test_file_drifts_stored(self):
        with self._store() as store:
            scan_id = store.save_scan(_make_result())
            drifts = store.get_file_drifts(scan_id)
            assert len(drifts) == 1
            assert drifts[0]["path"] == "setup.py"

    def test_triage_verdicts_stored(self):
        with self._store() as store:
            scan_id = store.save_scan(_make_result(), _make_triage())
            tvs = store.get_triage_verdicts(scan_id)
            assert len(tvs) == 1
            assert tvs[0]["ai_verdict"] == "malicious"
            assert tvs[0]["confidence"] == 95

    def test_stats(self):
        with self._store() as store:
            store.save_scan(_make_result(Verdict.CRITICAL))
            store.save_scan(
                AuditResult(
                    package="cleanpkg", version="2.0.0", verdict=Verdict.CLEAN,
                    files=[], pypi_file_count=3, github_file_count=3,
                )
            )
            stats = store.get_stats()
            assert stats["total_scans"] == 2
            assert stats["critical"] == 1
            assert stats["clean"] == 1

    def test_flagged_scans(self):
        with self._store() as store:
            store.save_scan(_make_result(Verdict.CRITICAL))
            store.save_scan(
                AuditResult(
                    package="cleanpkg", version="2.0.0", verdict=Verdict.CLEAN,
                    files=[], pypi_file_count=3, github_file_count=3,
                )
            )
            flagged = store.get_flagged_scans()
            assert len(flagged) == 1
            assert flagged[0]["package"] == "testpkg"

    def test_export_json(self):
        with self._store() as store:
            store.save_scan(_make_result(), _make_triage())
            data = store.export_json()
            assert len(data) == 1
            assert len(data[0]["triage_verdicts"]) == 1
