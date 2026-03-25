<p align="center">
  <img src="Vajra_logo.png" alt="Vajra" width="180">
  <h1 align="center">Vajra</h1>
  <p align="center"><strong>Zero-trust supply chain drift detection for PyPI packages</strong></p>
  <p align="center">
    <a href="https://0xparth.github.io/Vajra/">Live Dashboard</a> &middot;
    <a href="https://0xparth.github.io/Vajra/feed.json">JSON Feed</a> &middot;
    <a href="https://0xparth.github.io/Vajra/feed.xml">RSS Feed</a>
  </p>
</p>

---

Vajra compares every file in a PyPI source distribution against its corresponding GitHub tag using SHA-256 hashes. If a file exists on PyPI but not on GitHub — or if its content differs — Vajra flags it. No signatures, no heuristics databases. Just math.

Built in response to the [LiteLLM supply chain attack (March 2026)](https://docs.litellm.ai/blog/security-update-march-2026), where attackers published malicious versions to PyPI containing credential-stealing `.pth` files that auto-executed on every Python startup — code that never existed in the GitHub repository.

## The Problem

When you `pip install` a package, you're trusting that the code on PyPI matches the code on GitHub. But PyPI and GitHub are separate systems with no enforced link. An attacker who gains access to a PyPI maintainer account can upload *anything* — and did, in the case of LiteLLM 1.82.7 and 1.82.8.

The malicious versions contained:
- A `litellm_init.pth` file (auto-executes on Python startup, steals credentials)
- Modified `proxy_server.py` (reverse shell / data exfiltration)
- All without a single commit to GitHub

**Vajra makes this impossible to hide.**

## How Detection Works

Vajra uses a two-stage pipeline to keep scanning cheap and accurate:

### Stage 1 — Deterministic Drift Detection (free, zero false negatives)

```
  PyPI (.tar.gz)              GitHub (tag archive)
  ┌─────────────┐             ┌─────────────┐
  │ setup.py    │             │ setup.py    │
  │ __init__.py │  SHA-256    │ __init__.py │
  │ utils.py    │◄──compare──►│ utils.py    │
  │ evil.pth  ✗ │             │             │
  └─────────────┘             └─────────────┘
        │                           │
        └───── File tree diff ──────┘
                    │
              ┌─────┴─────┐
              │ CRITICAL:  │
              │ evil.pth   │  ← exists on PyPI, NOT on GitHub
              │ MATCH:     │
              │ setup.py   │  ← SHA-256 identical
              └────────────┘
```

1. Downloads the `.tar.gz` source distribution from PyPI
2. Identifies the GitHub repo from PyPI metadata, downloads the source at the matching tag
3. Compares file trees (set diff) and content hashes (SHA-256) for every common file
4. Classifies each discrepancy by severity using file-type rules

### Stage 2 — AI Triage (optional, Anthropic Claude)

5. For packages with flagged files, computes the actual `diff` and sends it to Claude
6. Claude classifies each change as **malicious**, **suspicious**, or **benign** with confidence scores and explanations

Stage 1 is free and catches 100% of injection attacks. Stage 2 costs ~$0.01-0.03 per package and helps distinguish real threats from build noise.

### Mass Drift Heuristic

Real supply chain attacks are surgical — the LiteLLM attacker touched exactly 3 files. But many legitimate packages (numpy, pandas) have hundreds of files that differ between PyPI and GitHub due to build processes, vendored dependencies, and C extensions.

Vajra handles this with a **mass drift heuristic**:

- If a package has **>15 actionable drifts** (warnings + criticals), it's flagged as "mass drift"
- Non-critical files are downgraded and tagged `[mass-drift]` — clearly packaging noise, not an attack
- **Always-critical files are never downgraded**: `.pth`, `.so`, `.dll`, `setup.py` stay CRITICAL regardless, because these are the highest-risk injection vectors
- Mass drift packages **skip AI triage** entirely — no point spending tokens analyzing 5,000 build artifacts

This keeps the signal-to-noise ratio high: a real attack will still light up red, even inside a package with heavy build noise.

## Installation

```bash
pip install git+https://github.com/0xParth/Vajra.git
```

From source:

```bash
git clone https://github.com/0xParth/Vajra.git
cd Vajra
pip install -e ".[dev]"
```

## Quick Start

```bash
# Audit a single package
vajra check requests 2.33.0

# See exactly what the LiteLLM attack looked like (local samples, no network)
vajra check litellm 1.82.8 --test-mode

# Compare against the clean version
vajra check litellm 1.82.6 --test-mode

# With AI analysis of flagged diffs
export ANTHROPIC_API_KEY=sk-ant-...
vajra check litellm 1.82.8 --triage
```

## CLI Reference

### `vajra check` — Audit a single package

```bash
vajra check <package> <version> [options]
```

| Flag | Description |
|------|-------------|
| `--triage` | Enable AI triage via Anthropic Claude |
| `--test-mode` | Use local samples instead of network (LiteLLM 1.82.6/1.82.8) |
| `--verbose` | Show all files, not just flagged ones |
| `--json` | Output results as JSON |
| `--check-all-versions` | Scan the last N versions for sudden changes |
| `--num-versions N` | How many versions to check (default: 5) |

### `vajra watch` — Batch scan top PyPI packages

```bash
vajra watch [options]
```

| Flag | Description |
|------|-------------|
| `--top N` | Scan top N most-downloaded packages (default: 100) |
| `--include-ai` | Also scan 148 curated AI/ML packages (LLM SDKs, agents, vector DBs) |
| `--triage` | Enable AI triage for flagged packages |
| `--dashboard` | Generate static dashboard after scanning |
| `--packages-file PATH` | Scan packages from a custom file (one per line) |
| `--output DIR` | Dashboard output directory |

```bash
# Scan top 100 + all major AI packages, with AI triage and dashboard
vajra watch --top 100 --include-ai --triage --dashboard
```

### `vajra dashboard` — Generate dashboard from existing data

```bash
vajra dashboard [--output DIR]
```

Generates:
- `index.html` — visual dashboard with stats, flagged packages, AI triage results
- `feed.json` — machine-readable JSON feed
- `feed.xml` — RSS feed

## Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| **CRITICAL** | High-risk injection vector — file exists on PyPI but not GitHub, or a known dangerous file type was modified | `.pth` file injected, `setup.py` modified, `.so`/`.dll` added |
| **WARNING** | Drift detected but lower risk — content mismatch or unexpected files | `__init__.py` content differs, extra `.py` files on PyPI |
| **INFO** | Expected packaging difference — safe to ignore | `PKG-INFO`, `.egg-info`, vendored dependencies |
| **OK** | SHA-256 match — file is identical on both PyPI and GitHub | Clean files |

## AI Triage Verdicts

When `--triage` is enabled, Claude analyzes the actual diffs of flagged files:

| Verdict | Meaning |
|---------|---------|
| **MALICIOUS** | Actively harmful — credential theft, backdoors, data exfiltration, reverse shells |
| **SUSPICIOUS** | Unusual patterns warranting investigation — obfuscated code, encoded payloads, unexpected network calls |
| **BENIGN** | Normal packaging difference — version bumps, build artifacts, auto-generated code |

## File Classification

Vajra uses a tiered classification system to decide what matters:

**Always Critical** (never downgraded, even in mass drift):
- `.pth` files — auto-execute on Python startup
- `.so` / `.dll` / `.dylib` — native code execution
- `setup.py` — runs arbitrary code during install

**High Risk**:
- `__init__.py`, `MANIFEST.in`, `conftest.py`

**Noise** (auto-classified as INFO):
- `PKG-INFO`, `SOURCES.txt`, `.egg-info/*`, `setup.cfg`

**Vendored** (auto-classified as INFO):
- `_vendor/*`, `vendor/*`, `third_party/*`, `_bundled/*`

**GitHub-only expected** (auto-classified as INFO):
- `.github/*`, `docs/*`, `examples/*`, `tests/*`, `.gitignore`, `Makefile`, `tox.ini`

## Configuration

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `GITHUB_TOKEN` | Recommended | GitHub API auth — 5,000 req/hr vs 60 unauthenticated |
| `ANTHROPIC_API_KEY` | For `--triage` | Anthropic API key for AI analysis |
| `VAJRA_TRIAGE_MODEL` | No | Override Claude model (default: `claude-sonnet-4-20250514`) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no anomalies detected |
| 1 | Warning — minor drift detected |
| 2 | Critical — high-risk anomalies found |

## Continuous Scanning with GitHub Actions

Vajra is designed to run as a scheduled GitHub Actions workflow with zero infrastructure cost:

```yaml
# .github/workflows/scan.yml
name: Vajra Scan
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }

      - uses: actions/cache@v4
        with:
          path: ~/.vajra/vajra.db
          key: vajra-db-${{ github.run_id }}
          restore-keys: vajra-db-

      - run: pip install .
      - run: vajra watch --top 100 --include-ai --triage --dashboard
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      - uses: actions/upload-pages-artifact@v3
        with: { path: dashboard }
  deploy:
    needs: scan
    permissions: { pages: write, id-token: write }
    environment: { name: github-pages }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/deploy-pages@v4
```

The SQLite database is cached between runs, so Vajra only scans packages whose latest version has changed since the last run.

## Project Structure

```
vajra/
├── cli.py             # Typer CLI — check, watch, dashboard commands
├── pypi.py            # PyPI JSON API client + sdist downloader
├── github.py          # GitHub API client + tag archive downloader
├── diff.py            # File tree diff, SHA-256 comparison, mass drift heuristic
├── triage.py          # AI triage via Anthropic Claude (rate-limited, retry-safe)
├── store.py           # SQLite persistence for scan results + triage verdicts
├── dashboard.py       # Static HTML + JSON/RSS feed generator
├── watch.py           # Batch scanner for top PyPI packages
├── reporter.py        # Rich terminal output
├── models.py          # Data models (AuditResult, FileDrift, TriageVerdict, etc.)
├── config.py          # File classification patterns + constants
├── ai_packages.py     # Curated list of 148 AI/ML packages
├── templates/
│   └── dashboard.html # Jinja2 template for the web dashboard
├── samples/           # Local test samples (LiteLLM clean vs malicious)
└── tests/             # Pytest test suite
```

## How It Caught the LiteLLM Attack

Running Vajra against the malicious LiteLLM 1.82.8 immediately surfaces the injection:

```
$ vajra check litellm 1.82.8 --test-mode

╭───────────────────────────────────────────────╮
│           VAJRA AUDIT — litellm 1.82.8        │
│              Verdict: CRITICAL                 │
╰───────────────────────────────────────────────╯

 CRITICAL  litellm_init.pth
           PyPI-only — file exists on PyPI but NOT on GitHub
           HIGH RISK: .pth files auto-execute on Python startup

 CRITICAL  setup.py
           SHA256 mismatch — modified between GitHub and PyPI

 WARNING   litellm/proxy_server.py
           SHA256 mismatch — reverse shell injected into proxy

 OK        litellm/__init__.py
           SHA256 match ✓
```

The `.pth` file was the primary payload — a 10-line script that ran on every Python startup, silently stealing environment variables (including API keys) and sending them to an attacker-controlled endpoint.

## Contributing

Contributions are welcome. Some areas that could use help:

- **More package ecosystems** — npm, crates.io, Go modules
- **Signature verification** — cross-reference with Sigstore/TUF when available
- **Better heuristics** — improve noise filtering for specific build systems (meson, CMake)
- **Webhook integrations** — Slack, Discord, PagerDuty alerts for critical findings

## Acknowledgments

- Inspired by the [LiteLLM security incident (March 2026)](https://docs.litellm.ai/blog/security-update-march-2026)
- Top package list from [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages)
- AI triage powered by [Anthropic Claude](https://docs.anthropic.com/)

## License

MIT
