<div align="center">

<img src="web/static/logo.png" alt="SpecterAI logo" width="220" />

# SpecterAI

**Attack Surface Intelligence Platform**: recon tool powered by Claude AI.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)

[Live Demo](https://specter-ai-8p3g.onrender.com) · [Report a Bug](https://github.com/hiratinspace/specter-ai/issues) · [Usage](#usage)

</div>

> **For authorized security testing only.** Do not scan systems you don't own or don't have explicit written permission to test.

---

## Screenshots

| Dashboard | Live Scan Progress | Report View |
|---|---|---|
| ![Dashboard](assets/screenshots/dashboard.png) | ![Scan progress](assets/screenshots/scan-progress.png) | ![Report](assets/screenshots/report.png) |

> The live demo runs on Render's free tier, so the first request after inactivity can take ~50s to wake up.

---

## Table of contents

- [What it does](#what-it-does)
- [How it works](#how-it-works)
- [Features](#features)
- [Usage](#usage)
  - [CLI](#cli)
  - [Web dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Requirements](#requirements)
- [Project structure](#project-structure)
- [License](#license)

---

## What it does

Runs four recon modules in parallel against a target domain or IP, then sends the aggregated findings to Claude for AI-driven analysis and risk assessment. Outputs a structured Markdown report, or view it live in the web dashboard with real-time progress over SSE.

| Module | What it collects |
|---|---|
| DNS / WHOIS | Subdomains, registrar info, DNS records |
| Port scan | Open ports (top 20 quick / top 1000 full), service banners |
| HTTP probe | Headers, server tech fingerprinting, security misconfigs |
| SSL/TLS | Certificate details, expiry, cipher weaknesses |

---

## How it works

```
target ─┬─▶ DNS / WHOIS enumeration ─┐
        ├─▶ Port scan + banner grab  ├─▶ aggregator ─▶ Claude (risk analysis) ─▶ report
        ├─▶ HTTP header probe        │        (CLI: Markdown file · Web: live dashboard)
        └─▶ SSL/TLS inspection ──────┘
```

The four modules run concurrently, and their results are merged into one structured summary. That summary is sent to Claude, which returns a risk level, key findings, and next steps as structured JSON, which then gets rendered into the final report.

---

## Features

- **Four recon modules run in parallel**: DNS/WHOIS, port scanning with banner grabbing, HTTP header analysis, SSL/TLS inspection
- **AI-driven risk assessment** via Claude: executive summary, key findings, and recommended next steps
- **Live web dashboard** with real-time scan progress over Server-Sent Events, plus scan history per browser session
- **CLI mode** for scripting or offline use (`--no-ai` skips the Claude call entirely)
- **Quick or full scan modes**: top 20 ports for a fast pass, top 1000 for deeper coverage
- **Rate limited** (5 scans per IP per minute on the web dashboard) to keep the demo usable for everyone
- **Exportable reports**: Markdown download or raw JSON via the dashboard

---

## Usage

### CLI

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here

python specter-ai.py --target example.com --mode quick
python specter-ai.py --target example.com --mode full --output report.md
python specter-ai.py --target example.com --no-ai   # skip AI analysis
```

**Flags**

| Flag | Description |
|---|---|
| `--target / -t` | Target domain or IP (required) |
| `--mode / -m` | `quick` (top 20 ports) or `full` (top 1000). Default: `quick` |
| `--output / -o` | Output filename. Default: `<target>_report.md` |
| `--no-ai` | Skip Claude analysis (offline / no API key) |

### Web dashboard

```bash
python3 web/app.py
# Open http://localhost:5000
```

Real-time scan progress via SSE, with a full report view and scan history on completion. Try it against a legal test target:

```bash
python3 specter-ai.py --target scanme.nmap.org
```

---

## Configuration

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For AI analysis | Claude API key. Omit and pass `--no-ai` (CLI) or disable "AI Analysis" (web) to run without it |
| `SECRET_KEY` | Optional | Flask session signing key for the web dashboard. Falls back to a random key generated per process restart |

---

## Requirements

- Python 3.10+
- `ANTHROPIC_API_KEY` environment variable (for AI analysis)

```
anthropic>=0.25.0
dnspython>=2.4.0
python-whois>=0.9.0
requests>=2.31.0
flask>=3.0.0
gunicorn>=21.2.0
```

---

## Project structure

```
specter-ai.py        # CLI entrypoint
web/app.py           # Flask web dashboard
modules/             # dns_enum, port_scan, http_probe, ssl_check
core/                # aggregator, ai_analyst (Claude integration)
report/              # Markdown report generator
assets/screenshots/  # README screenshots
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

---

<div align="center">

Built with Python, by **Hirat Rahman Rahi**, first released April 8, 2026.

</div>
