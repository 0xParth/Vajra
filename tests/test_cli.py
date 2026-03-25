"""Integration tests for the Vajra CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from vajra.cli import app

runner = CliRunner()


class TestCLITestMode:
    def test_clean_version_passes(self):
        result = runner.invoke(app, ["check", "litellm", "1.82.6", "--test-mode"])
        assert result.exit_code in (0, 1)
        assert "Vajra Audit" in result.output or "PASS" in result.output or "WARN" in result.output

    def test_malicious_version_fails(self):
        result = runner.invoke(app, ["check", "litellm", "1.82.8", "--test-mode"])
        assert result.exit_code == 2
        assert "CRITICAL" in result.output or "FAIL" in result.output

    def test_malicious_flags_pth(self):
        result = runner.invoke(app, ["check", "litellm", "1.82.8", "--test-mode", "--verbose"])
        assert "litellm_init.pth" in result.output

    def test_malicious_flags_proxy_server(self):
        result = runner.invoke(app, ["check", "litellm", "1.82.8", "--test-mode", "--verbose"])
        assert "proxy_server" in result.output

    def test_json_output(self):
        result = runner.invoke(app, ["check", "litellm", "1.82.8", "--test-mode", "--json"])
        assert '"verdict"' in result.output or "CRITICAL" in result.output

    def test_missing_sample_exits(self):
        result = runner.invoke(app, ["check", "nonexistent", "0.0.0", "--test-mode"])
        assert result.exit_code != 0


class TestCLIVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert "0.1.0" in result.output

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        assert "Usage" in result.output
