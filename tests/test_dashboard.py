"""Tests for the dashboard generator."""

from __future__ import annotations

import tempfile
from pathlib import Path

from vajra.dashboard import generate_dashboard
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


def _seed_store(store: VajraStore) -> None:
    store.save_scan(
        AuditResult(
            package="litellm", version="1.82.8", verdict=Verdict.CRITICAL,
            github_repo="BerriAI/litellm", github_tag="v1.82.8",
            github_tag_exists=True,
            files=[
                FileDrift("litellm_init.pth", DriftType.PYPI_ONLY, Severity.CRITICAL,
                          pypi_sha256="abc", detail="HIGH RISK"),
            ],
            pypi_file_count=5, github_file_count=3,
        ),
        [
            TriageVerdict("litellm_init.pth", AIVerdict.MALICIOUS, 98,
                          "credential_theft", "Encoded credential stealer."),
        ],
    )
    store.save_scan(
        AuditResult(
            package="requests", version="2.31.0", verdict=Verdict.CLEAN,
            github_repo="psf/requests", github_tag="v2.31.0",
            github_tag_exists=True, files=[],
            pypi_file_count=50, github_file_count=50,
        )
    )


class TestDashboardGeneration:
    def test_generates_index_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            out_dir = Path(tmpdir) / "public"

            with VajraStore(db_path) as store:
                _seed_store(store)
                result = generate_dashboard(store, out_dir)

            assert (result / "index.html").exists()
            html = (result / "index.html").read_text()
            assert "litellm" in html
            assert "CRITICAL" in html

    def test_generates_json_feed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            out_dir = Path(tmpdir) / "public"

            with VajraStore(db_path) as store:
                _seed_store(store)
                result = generate_dashboard(store, out_dir)

            feed_path = result / "feed.json"
            assert feed_path.exists()
            import json
            data = json.loads(feed_path.read_text())
            assert "findings" in data
            assert "stats" in data

    def test_generates_rss_feed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            out_dir = Path(tmpdir) / "public"

            with VajraStore(db_path) as store:
                _seed_store(store)
                result = generate_dashboard(store, out_dir)

            rss_path = result / "feed.xml"
            assert rss_path.exists()
            content = rss_path.read_text()
            assert "litellm" in content
            assert "CRITICAL" in content

    def test_empty_store_still_generates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            out_dir = Path(tmpdir) / "public"

            with VajraStore(db_path) as store:
                result = generate_dashboard(store, out_dir)

            assert (result / "index.html").exists()
