"""AI triage module — uses Anthropic Claude to analyze flagged diffs."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from rich.console import Console

from vajra.config import MAX_DIFF_CHARS, TRIAGE_MODEL, anthropic_api_key

_MIN_INTERVAL = 15.0  # seconds between API calls (stays under 30K tokens/min)
_last_call_time: float = 0.0
_triage_lock = asyncio.Lock()
from vajra.diff import content_diff
from vajra.models import (
    AIVerdict,
    AuditResult,
    DriftType,
    FileDrift,
    Severity,
    TriageVerdict,
)

console = Console(stderr=True)

SYSTEM_PROMPT = """\
You are a supply chain security analyst. You are given diffs or file contents \
from a Python package where the PyPI-published artifact differs from the \
GitHub source repository.

Your job is to determine whether each change is:
- "malicious": actively harmful (credential theft, backdoor, data exfiltration, \
  crypto mining, reverse shell, etc.)
- "suspicious": unusual and warrants investigation (obfuscated code, unexpected \
  network calls, encoded payloads, etc.)
- "benign": normal packaging difference (version bumps, auto-generated files, \
  build artifacts, whitespace changes, etc.)

Respond ONLY with a JSON array. Each element must have:
{
  "file_path": "<relative path>",
  "verdict": "malicious" | "suspicious" | "benign",
  "confidence": <0-100>,
  "threat_category": "<category>",
  "explanation": "<1-2 sentence explanation>"
}

Threat categories: credential_theft, backdoor, data_exfil, code_injection, \
crypto_miner, reverse_shell, obfuscated_payload, benign_build, version_bump, \
packaging_artifact, unknown.

Be precise. Do not hallucinate threats. If a change is clearly benign, say so."""


def _needs_triage(f: FileDrift) -> bool:
    return (
        f.drift_type in (DriftType.PYPI_ONLY, DriftType.CONTENT_MISMATCH)
        and f.severity in (Severity.CRITICAL, Severity.WARNING)
    )


def _build_user_prompt(
    package: str,
    version: str,
    file_analyses: list[dict[str, str]],
) -> str:
    parts = [
        f"Package: {package}=={version}",
        f"Number of flagged files: {len(file_analyses)}",
        "",
    ]
    for i, fa in enumerate(file_analyses, 1):
        parts.append(f"--- File {i}: {fa['path']} ({fa['drift_type']}) ---")
        parts.append(fa["content"])
        parts.append("")
    return "\n".join(parts)


async def triage_audit(
    result: AuditResult,
    pypi_dir: Path,
    github_dir: Path,
) -> list[TriageVerdict]:
    """Run AI triage on flagged files from an audit result.

    Returns a list of TriageVerdict for each analyzed file.
    """
    api_key = anthropic_api_key()
    if not api_key:
        console.print(
            "[red]ANTHROPIC_API_KEY not set. Cannot run AI triage.[/red]\n"
            "[dim]Set it: export ANTHROPIC_API_KEY=sk-ant-...[/dim]"
        )
        return []

    flagged = [f for f in result.files if _needs_triage(f)]
    if not flagged:
        console.print("[green]No files require AI triage.[/green]")
        return []

    file_analyses: list[dict[str, str]] = []
    for f in flagged:
        diff_text = content_diff(pypi_dir, github_dir, f)
        if len(diff_text) > MAX_DIFF_CHARS:
            diff_text = diff_text[:MAX_DIFF_CHARS] + "\n... (truncated)"
        file_analyses.append({
            "path": f.path,
            "drift_type": f.drift_type.value,
            "content": diff_text,
        })

    user_prompt = _build_user_prompt(result.package, result.version, file_analyses)

    try:
        import anthropic
    except ImportError:
        console.print("[red]anthropic package not installed. Run: pip install anthropic[/red]")
        return []

    client = anthropic.AsyncAnthropic(api_key=api_key)
    max_retries = 3

    for attempt in range(1, max_retries + 1):
        try:
            global _last_call_time
            async with _triage_lock:
                elapsed = time.monotonic() - _last_call_time
                if elapsed < _MIN_INTERVAL:
                    await asyncio.sleep(_MIN_INTERVAL - elapsed)
                _last_call_time = time.monotonic()

            with console.status("[cyan]Running AI triage on flagged files..."):
                response = await client.messages.create(
                    model=TRIAGE_MODEL,
                    max_tokens=2048,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                )

            raw_text = response.content[0].text.strip()
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3]

            return _parse_response(raw_text, flagged)

        except anthropic.APIStatusError as e:
            if e.status_code in (429, 529) and attempt < max_retries:
                wait = 15 * attempt
                console.print(
                    f"[yellow]API overloaded (attempt {attempt}/{max_retries}), "
                    f"retrying in {wait}s...[/yellow]"
                )
                await asyncio.sleep(wait)
                continue
            console.print(f"[red]AI triage failed: {e}[/red]")
            return _fallback_verdicts(flagged, f"Triage failed: {e}")

        except Exception as e:
            console.print(f"[red]AI triage failed: {e}[/red]")
            return _fallback_verdicts(flagged, f"Triage failed: {e}")

    return _fallback_verdicts(flagged, "Triage failed after retries")


def _parse_response(
    raw_text: str, flagged: list[FileDrift]
) -> list[TriageVerdict]:
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("[")
        end = raw_text.rfind("]") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(raw_text[start:end])
            except json.JSONDecodeError:
                return _fallback_verdicts(flagged, "Failed to parse AI response")
        else:
            return _fallback_verdicts(flagged, "Failed to parse AI response")

    if not isinstance(data, list):
        data = [data]

    verdicts: list[TriageVerdict] = []
    for item in data:
        verdict_str = item.get("verdict", "suspicious").lower()
        try:
            ai_verdict = AIVerdict(verdict_str)
        except ValueError:
            ai_verdict = AIVerdict.SUSPICIOUS

        verdicts.append(
            TriageVerdict(
                file_path=item.get("file_path", "unknown"),
                ai_verdict=ai_verdict,
                confidence=int(item.get("confidence", 50)),
                threat_category=item.get("threat_category", "unknown"),
                explanation=item.get("explanation", ""),
            )
        )

    return verdicts


def _fallback_verdicts(
    flagged: list[FileDrift], reason: str
) -> list[TriageVerdict]:
    return [
        TriageVerdict(
            file_path=f.path,
            ai_verdict=AIVerdict.ERROR,
            confidence=0,
            threat_category="error",
            explanation=reason,
        )
        for f in flagged
    ]
