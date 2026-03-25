"""Tests for the triage module — mocked, no real API calls."""

from __future__ import annotations

from vajra.models import AIVerdict, TriageVerdict
from vajra.triage import _parse_response, _needs_triage
from vajra.models import DriftType, FileDrift, Severity


class TestNeedsTriage:
    def test_pypi_only_critical(self):
        f = FileDrift("bad.pth", DriftType.PYPI_ONLY, Severity.CRITICAL)
        assert _needs_triage(f)

    def test_content_mismatch_warning(self):
        f = FileDrift("readme.txt", DriftType.CONTENT_MISMATCH, Severity.WARNING)
        assert _needs_triage(f)

    def test_match_does_not_need_triage(self):
        f = FileDrift("ok.py", DriftType.MATCH, Severity.OK)
        assert not _needs_triage(f)

    def test_noise_does_not_need_triage(self):
        f = FileDrift("PKG-INFO", DriftType.PYPI_ONLY, Severity.INFO)
        assert not _needs_triage(f)


class TestParseResponse:
    def test_valid_json_array(self):
        raw = """[
            {
                "file_path": "setup.py",
                "verdict": "malicious",
                "confidence": 95,
                "threat_category": "backdoor",
                "explanation": "Injected payload."
            }
        ]"""
        flagged = [FileDrift("setup.py", DriftType.CONTENT_MISMATCH, Severity.CRITICAL)]
        verdicts = _parse_response(raw, flagged)
        assert len(verdicts) == 1
        assert verdicts[0].ai_verdict == AIVerdict.MALICIOUS
        assert verdicts[0].confidence == 95

    def test_json_with_markdown_wrapper(self):
        raw = """```json
        [{"file_path": "x.pth", "verdict": "suspicious", "confidence": 70,
          "threat_category": "obfuscated_payload", "explanation": "Encoded exec."}]
        ```"""
        flagged = [FileDrift("x.pth", DriftType.PYPI_ONLY, Severity.CRITICAL)]
        verdicts = _parse_response(raw, flagged)
        assert len(verdicts) == 1
        assert verdicts[0].ai_verdict == AIVerdict.SUSPICIOUS

    def test_benign_verdict(self):
        raw = '[{"file_path": "v.py", "verdict": "benign", "confidence": 90, "threat_category": "version_bump", "explanation": "Version changed."}]'
        flagged = [FileDrift("v.py", DriftType.CONTENT_MISMATCH, Severity.WARNING)]
        verdicts = _parse_response(raw, flagged)
        assert verdicts[0].ai_verdict == AIVerdict.BENIGN

    def test_invalid_json_returns_error(self):
        raw = "this is not json at all"
        flagged = [FileDrift("bad.py", DriftType.PYPI_ONLY, Severity.CRITICAL)]
        verdicts = _parse_response(raw, flagged)
        assert len(verdicts) == 1
        assert verdicts[0].ai_verdict == AIVerdict.ERROR

    def test_unknown_verdict_maps_to_suspicious(self):
        raw = '[{"file_path": "x.py", "verdict": "maybe_bad", "confidence": 50, "threat_category": "unknown", "explanation": "Unclear."}]'
        flagged = [FileDrift("x.py", DriftType.CONTENT_MISMATCH, Severity.CRITICAL)]
        verdicts = _parse_response(raw, flagged)
        assert verdicts[0].ai_verdict == AIVerdict.SUSPICIOUS
