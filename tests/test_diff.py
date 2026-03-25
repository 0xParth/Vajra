"""Unit tests for the Vajra diff engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

from vajra.config import is_high_risk, is_noise, is_github_only_expected
from vajra.diff import compute_sha256, normalize_tree, run_audit
from vajra.models import DriftType, Severity, Verdict

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
GITHUB_CLEAN = SAMPLES / "litellm_1_82_6_github"
PYPI_CLEAN = SAMPLES / "litellm_1_82_6_pypi"
GITHUB_1828 = SAMPLES / "litellm_1_82_8_github"
PYPI_MALICIOUS = SAMPLES / "litellm_1_82_8_pypi"


class TestFileClassification:
    def test_pth_is_high_risk(self):
        assert is_high_risk("litellm_init.pth")

    def test_setup_py_is_high_risk(self):
        assert is_high_risk("setup.py")

    def test_init_py_is_high_risk(self):
        assert is_high_risk("litellm/__init__.py")

    def test_regular_py_not_high_risk(self):
        assert not is_high_risk("litellm/utils.py")

    def test_so_is_high_risk(self):
        assert is_high_risk("litellm/_speedup.so")

    def test_pkg_info_is_noise(self):
        assert is_noise("PKG-INFO")

    def test_sources_txt_is_noise(self):
        assert is_noise("SOURCES.txt")

    def test_egg_info_is_noise(self):
        assert is_noise("litellm.egg-info/top_level.txt")

    def test_regular_file_not_noise(self):
        assert not is_noise("litellm/proxy_server.py")

    def test_gitignore_is_github_only_expected(self):
        assert is_github_only_expected(".gitignore")

    def test_github_dir_is_expected(self):
        assert is_github_only_expected(".github/workflows/ci.yml")

    def test_license_is_expected(self):
        assert is_github_only_expected("LICENSE")


class TestSHA256:
    def test_consistent_hash(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello world")
            f.flush()
            h1 = compute_sha256(Path(f.name))
            h2 = compute_sha256(Path(f.name))
        assert h1 == h2
        assert len(h1) == 64

    def test_different_content_different_hash(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f1:
            f1.write(b"hello")
            f1.flush()
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f2:
                f2.write(b"world")
                f2.flush()
                assert compute_sha256(Path(f1.name)) != compute_sha256(Path(f2.name))


class TestNormalizeTree:
    def test_returns_dict_with_posix_paths(self):
        tree = normalize_tree(GITHUB_CLEAN)
        assert isinstance(tree, dict)
        assert all("/" in k or "/" not in k for k in tree.keys())
        for path in tree:
            assert "\\" not in path

    def test_clean_github_has_expected_files(self):
        tree = normalize_tree(GITHUB_CLEAN)
        assert "litellm/__init__.py" in tree
        assert "litellm/proxy_server.py" in tree
        assert "setup.py" in tree


class TestCleanAudit:
    """v1.82.6 — PyPI and GitHub should be identical (minus PKG-INFO)."""

    def test_clean_version_verdict(self):
        pypi_tree = normalize_tree(PYPI_CLEAN)
        github_tree = normalize_tree(GITHUB_CLEAN)
        result = run_audit(
            pypi_tree, github_tree,
            package="litellm", version="1.82.6",
        )
        assert result.verdict in (Verdict.CLEAN, Verdict.WARN)
        assert result.critical_count == 0

    def test_clean_version_all_files_match_or_noise(self):
        pypi_tree = normalize_tree(PYPI_CLEAN)
        github_tree = normalize_tree(GITHUB_CLEAN)
        result = run_audit(
            pypi_tree, github_tree,
            package="litellm", version="1.82.6",
        )
        for f in result.files:
            assert f.severity in (Severity.OK, Severity.INFO, Severity.WARNING), (
                f"Unexpected severity {f.severity} for {f.path}"
            )


class TestMaliciousAudit:
    """v1.82.8 — PyPI has injected .pth and modified proxy_server.py."""

    def _run(self):
        pypi_tree = normalize_tree(PYPI_MALICIOUS)
        github_tree = normalize_tree(GITHUB_1828)
        return run_audit(
            pypi_tree, github_tree,
            package="litellm", version="1.82.8",
        )

    def test_verdict_is_critical(self):
        result = self._run()
        assert result.verdict == Verdict.CRITICAL

    def test_pth_file_flagged_critical(self):
        result = self._run()
        pth_files = [
            f for f in result.files if f.path == "litellm_init.pth"
        ]
        assert len(pth_files) == 1
        assert pth_files[0].drift_type == DriftType.PYPI_ONLY
        assert pth_files[0].severity == Severity.CRITICAL

    def test_proxy_server_content_mismatch(self):
        result = self._run()
        proxy_files = [
            f for f in result.files if f.path == "litellm/proxy_server.py"
        ]
        assert len(proxy_files) == 1
        assert proxy_files[0].drift_type == DriftType.CONTENT_MISMATCH
        assert proxy_files[0].severity == Severity.CRITICAL

    def test_init_py_matches(self):
        result = self._run()
        init_files = [
            f for f in result.files if f.path == "litellm/__init__.py"
        ]
        assert len(init_files) == 1
        assert init_files[0].drift_type == DriftType.MATCH
        assert init_files[0].severity == Severity.OK

    def test_pkg_info_is_noise(self):
        result = self._run()
        pkg_files = [
            f for f in result.files if f.path == "PKG-INFO"
        ]
        assert len(pkg_files) == 1
        assert pkg_files[0].severity == Severity.INFO

    def test_critical_count(self):
        result = self._run()
        assert result.critical_count >= 2


class TestNoGitHubTag:
    def test_missing_tag_is_critical(self):
        pypi_tree = normalize_tree(PYPI_CLEAN)
        result = run_audit(
            pypi_tree, {},
            package="litellm", version="9.99.99",
            github_tag_exists=False,
        )
        assert result.verdict == Verdict.CRITICAL
        meta_files = [
            f for f in result.files if f.drift_type == DriftType.NO_GITHUB_TAG
        ]
        assert len(meta_files) == 1
        assert meta_files[0].severity == Severity.CRITICAL
