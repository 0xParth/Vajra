# Vajra

**Source-to-Artifact Drift Detector for Python Packages**

Vajra compares a PyPI source distribution against its corresponding GitHub tag to detect supply chain attacks — files injected into PyPI that never existed in the source repo.

Built in response to the [LiteLLM March 2026 compromise](https://docs.litellm.ai/blog/security-update-march-2026), where attackers uploaded malicious versions (1.82.7, 1.82.8) containing credential-stealing `.pth` files that auto-executed on every Python startup.

## How it works

**Stage 1 — Deterministic drift detection (zero false negatives)**
1. Downloads the source distribution (`.tar.gz`) from PyPI for the specified version.
2. Identifies the GitHub repo from PyPI metadata. Downloads the source at the matching tag.
3. Compares file trees (set operations) and content hashes (SHA256). Flags any divergence.

**Stage 2 — AI triage (Anthropic Claude, optional)**
4. For flagged files, computes the actual diff and sends it to Claude for security analysis.
5. Claude classifies each change as `malicious`, `suspicious`, or `benign` with confidence scores.

This two-stage pipeline means you scan thousands of packages cheaply (Stage 1 is free), and only pay for AI analysis on the tiny fraction that actually drifted.

## Install

```bash
pip install .
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Usage

### Basic audit

```bash
vajra check <package> <version>
```

### With AI triage

```bash
export ANTHROPIC_API_KEY=sk-ant-...
vajra check litellm 1.82.8 --triage
```

### Test mode (local samples, no network)

```bash
vajra check litellm 1.82.8 --test-mode
vajra check litellm 1.82.6 --test-mode   # clean version for comparison
```

### Verbose / JSON output

```bash
vajra check litellm 1.82.8 --test-mode --verbose
vajra check litellm 1.82.8 --test-mode --json
```

### Recon mode (bug bounty)

Scan the last N versions for sudden changes in maintainer or file structure:

```bash
vajra check litellm 1.82.8 --check-all-versions
vajra check litellm 1.82.8 --check-all-versions --num-versions 10
```

### Batch scanning (watch mode)

Scan the top N most-downloaded PyPI packages automatically:

```bash
vajra watch --top 50
vajra watch --top 100 --triage --dashboard
vajra watch --packages-file my-packages.txt --triage
```

### Generate dashboard

Regenerate the static dashboard from existing scan data:

```bash
vajra dashboard
vajra dashboard --output ./public
```

The dashboard generates:
- `index.html` — visual report with stats, flagged packages, and AI triage results
- `feed.json` — machine-readable JSON feed for integration with other tools
- `feed.xml` — RSS feed for subscribers

## Severity levels

| Color  | Meaning |
|--------|---------|
| GREEN  | File hashes match between PyPI and GitHub |
| YELLOW | Minor drift — packaging artifacts, expected GitHub-only files |
| RED    | High-risk anomaly — injected executables, modified setup scripts, missing tags |

## AI triage verdicts

When `--triage` is enabled, flagged diffs are analyzed by Claude:

| Verdict    | Meaning |
|------------|---------|
| MALICIOUS  | Actively harmful (credential theft, backdoor, data exfiltration) |
| SUSPICIOUS | Unusual, warrants investigation (obfuscated code, encoded payloads) |
| BENIGN     | Normal packaging difference (version bumps, build artifacts) |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | GitHub API auth (5,000 req/hr vs 60 unauthenticated) |
| `ANTHROPIC_API_KEY` | Required for `--triage` (AI analysis of flagged diffs) |
| `VAJRA_TRIAGE_MODEL` | Override Claude model (default: `claude-sonnet-4-20250514`) |

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Clean — no anomalies |
| 1    | Warning — minor drift detected |
| 2    | Critical — high-risk anomalies found |

## Project structure

```
vajra/
  cli.py          # Typer CLI (check, watch, dashboard)
  pypi.py         # PyPI API client + sdist downloader
  github.py       # GitHub API client + tag archive downloader
  diff.py         # File tree diff + content hash + unified diffs
  triage.py       # AI triage via Anthropic Claude
  store.py        # SQLite persistence for scan results
  dashboard.py    # Static HTML + JSON/RSS feed generator
  watch.py        # Batch scanner for top PyPI packages
  reporter.py     # Rich console output
  models.py       # Data models
  config.py       # Constants + file classification patterns
templates/        # Jinja2 templates for dashboard
samples/          # Local test samples (clean vs malicious)
tests/            # Pytest test suite (53 tests)
```

## License

MIT
