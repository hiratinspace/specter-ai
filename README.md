# specter-ai

Attack Surface Intelligence Platform — recon tool powered by Claude AI.

> **For authorized security testing only.** Do not scan systems you don't own or have explicit written permission to test.

Built with Python and Claude Code.

By **Hirat Rahman Rahi** — first released April 8, 2026.

---

## What it does

Runs four recon modules in parallel against a target domain or IP, then sends the aggregated findings to Claude for AI-driven analysis and risk assessment. Outputs a structured Markdown report.

| Module | What it collects |
|---|---|
| DNS / WHOIS | Subdomains, registrar info, DNS records |
| Port scan | Open ports (top 20 quick / top 1000 full) |
| HTTP probe | Headers, server info, security misconfigs |
| SSL/TLS | Certificate details, cipher weaknesses |

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

### Web Dashboard

```bash
python web/app.py
# Open http://localhost:5000
```

Real-time scan progress via SSE, with a full report view and scan history on completion.

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
```

---

## Project structure

```
specter-ai.py        # CLI entrypoint
web/app.py           # Flask web dashboard
modules/             # dns_enum, port_scan, http_probe, ssl_check
core/                # aggregator, ai_analyst (Claude integration)
report/              # Markdown report generator
```
