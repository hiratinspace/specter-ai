"""
generator.py — Markdown Pentest Report Generator
Produces a clean, structured markdown report from aggregated recon + AI analysis.

Sample usage:
    from report.generator import generate_report
    path = generate_report("example.com", aggregated, ai_analysis, "report.md")
"""

import os
from datetime import datetime, timezone


SEVERITY_EMOJI = {
    "critical":      "🔴",
    "high":          "🟠",
    "medium":        "🟡",
    "low":           "🟢",
    "info":          "🔵",
    "informational": "🔵",
    "unknown":       "⚪",
}

RISK_BADGE = {
    "critical": "**🔴 CRITICAL**",
    "high":     "**🟠 HIGH**",
    "medium":   "**🟡 MEDIUM**",
    "low":      "**🟢 LOW**",
    "unknown":  "**⚪ UNKNOWN**",
}


def _hr():
    return "\n---\n"


def _section(title):
    return f"\n## {title}\n"


def _subsection(title):
    return f"\n### {title}\n"


def render_meta(target, data, ai):
    meta = data.get("meta", {})
    risk = ai.get("risk_level", "unknown").lower()
    badge = RISK_BADGE.get(risk, f"**{risk.upper()}**")

    lines = [
        "# Specter AI — Attack Surface Intelligence Report",
        "",
        f"> **DISCLAIMER:** This report was generated for authorized security testing only.",
        f"> Unauthorized use of this tool or its findings is illegal.",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Target** | `{target}` |",
        f"| **Scan Mode** | {meta.get('scan_mode', 'N/A')} |",
        f"| **Scanned At** | {meta.get('scanned_at', 'N/A')} |",
        f"| **Report Generated** | {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| **Overall Risk** | {badge} |",
    ]
    return "\n".join(lines)


def render_executive_summary(ai):
    lines = [_section("Executive Summary")]
    summary = ai.get("executive_summary", "No summary available.")
    attack_surface = ai.get("attack_surface", "")

    lines.append(summary)
    if attack_surface:
        lines.append("")
        lines.append(f"**Attack Surface:** {attack_surface}")

    observations = ai.get("interesting_observations", [])
    if observations:
        lines.append("")
        lines.append("**Notable Observations:**")
        for obs in observations:
            lines.append(f"- {obs}")

    return "\n".join(lines)


def render_target_info(data):
    dns   = data.get("dns", {})
    whois = dns.get("whois", {})
    ports = data.get("ports", {})

    lines = [_section("Target Information")]

    # IPs
    ips = dns.get("ip_addresses", [])
    if ips:
        lines.append(f"**IP Addresses:** {', '.join(f'`{ip}`' for ip in ips)}")

    # WHOIS
    if whois and not whois.get("error"):
        lines.append("")
        lines.append(_subsection("WHOIS Registration"))
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        for k, v in [
            ("Registrar",    whois.get("registrar", "N/A")),
            ("Organization", whois.get("org",       "N/A")),
            ("Country",      whois.get("country",   "N/A")),
            ("Created",      whois.get("created",   "N/A")),
            ("Expires",      whois.get("expires",   "N/A")),
        ]:
            lines.append(f"| {k} | {v} |")

        ns = whois.get("name_servers", [])
        if ns:
            lines.append(f"\n**Name Servers:** {', '.join(f'`{n}`' for n in ns[:6])}")

    # DNS Records
    records = dns.get("records", {})
    if records:
        lines.append(_subsection("DNS Records"))
        for rtype, values in records.items():
            lines.append(f"**{rtype}:**")
            for v in values:
                lines.append(f"- `{v}`")
            lines.append("")

    # Subdomains
    subdomains = dns.get("subdomains", [])
    if subdomains:
        lines.append(_subsection("Discovered Subdomains"))
        for sub in subdomains:
            ips = sub.get("ips", [])
            ip_str = f" → {', '.join(f'`{ip}`' for ip in ips)}" if ips else ""
            lines.append(f"- `{sub['subdomain']}`{ip_str}")

    return "\n".join(lines)


def render_ports(data):
    ports = data.get("ports", {})
    open_ports = ports.get("open_ports", [])

    lines = [_section("Open Ports & Services")]

    stats = (
        f"Scanned **{ports.get('ports_scanned', 0)}** ports on "
        f"`{ports.get('target_ip', 'N/A')}` in "
        f"**{ports.get('scan_time_s', 0)}s** — "
        f"found **{ports.get('open_count', 0)}** open port(s)."
    )
    lines.append(stats)

    if not open_ports:
        lines.append("\n_No open ports found._")
        return "\n".join(lines)

    lines.append("")
    lines.append("| Port | Service | Banner |")
    lines.append("|------|---------|--------|")
    for p in open_ports:
        banner = p.get("banner") or "—"
        banner = banner.replace("|", "\\|")[:80]  # sanitize for markdown table
        lines.append(f"| `{p['port']}` | {p.get('service', 'unknown')} | `{banner}` |")

    return "\n".join(lines)


def render_http(data):
    http = data.get("http", {})

    lines = [_section("Web Technology & HTTP Analysis")]

    # Status codes
    codes = http.get("status_codes", {})
    if codes:
        lines.append(_subsection("HTTP Status Codes"))
        for url, code in codes.items():
            lines.append(f"- `{url}` → **{code}**")

    # Redirects
    redirects = http.get("redirects", [])
    if redirects:
        lines.append("")
        lines.append(f"**Redirect chain:** {' → '.join(f'`{r}`' for r in redirects)}")

    # Server headers
    server_headers = http.get("server_headers", {})
    if server_headers:
        lines.append(_subsection("Technology Headers"))
        lines.append("| Header | Value |")
        lines.append("|--------|-------|")
        for k, v in server_headers.items():
            lines.append(f"| `{k}` | `{v}` |")

    # Detected technologies
    techs = http.get("technologies", [])
    if techs:
        lines.append(_subsection("Detected Technologies"))
        lines.append(", ".join(f"`{t}`" for t in sorted(techs)))

    # Security headers
    present = http.get("security_headers_present", [])
    missing = http.get("security_headers_missing", [])

    lines.append(_subsection("Security Headers"))
    lines.append(f"**Present ({len(present)}):** " + (", ".join(f"`{h}`" for h in present) or "_none_"))
    lines.append("")

    if missing:
        lines.append(f"**Missing ({len(missing)}) — potential vulnerabilities:**")
        for h in missing:
            lines.append(f"- ⚠️  `{h}`")

    # Cookie issues
    cookies = http.get("cookies", [])
    if cookies:
        lines.append(_subsection("Cookie Security Issues"))
        for c in cookies:
            lines.append(f"- **`{c['name']}`**: {', '.join(c['issues'])}")

    return "\n".join(lines)


def render_ssl(data):
    ssl_data = data.get("ssl", {})
    primary  = ssl_data.get("primary_cert")
    findings = ssl_data.get("findings", [])

    lines = [_section("SSL / TLS Analysis")]

    if primary:
        lines.append(_subsection("Certificate Details"))
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")

        subj = primary.get("subject", {})
        issuer = primary.get("issuer", {})
        expiry_label = (
            f"⚠️ **EXPIRED** ({abs(primary.get('days_until_expiry', 0))} days ago)"
            if primary.get("is_expired") else
            f"⚠️ Expiring in {primary.get('days_until_expiry')} days"
            if primary.get("expiring_soon") else
            f"{primary.get('not_after')} ({primary.get('days_until_expiry')} days remaining)"
        )

        for k, v in [
            ("Subject CN",     subj.get("common_name", "N/A")),
            ("Issuer",         issuer.get("org", issuer.get("common_name", "N/A"))),
            ("Protocol",       primary.get("protocol", "N/A")),
            ("Cipher",         primary.get("cipher", "N/A")),
            ("Key Bits",       str(primary.get("key_bits", "N/A"))),
            ("Valid From",     primary.get("not_before", "N/A")),
            ("Expiry",         expiry_label),
            ("Self-Signed",    "⚠️ YES" if primary.get("self_signed") else "No"),
        ]:
            lines.append(f"| {k} | {v} |")

        sans = primary.get("sans", [])
        if sans:
            lines.append(f"\n**Subject Alternative Names ({len(sans)}):**")
            for san in sans[:10]:
                lines.append(f"- `{san}`")

    # SSL Findings
    if findings:
        lines.append(_subsection("SSL/TLS Findings"))
        for f in findings:
            emoji = SEVERITY_EMOJI.get(f.get("severity", "info"), "⚪")
            lines.append(f"- {emoji} `Port {f.get('port', '?')}` — {f.get('finding', '')}")
    elif primary:
        lines.append("\n✅ No SSL/TLS issues detected.")

    return "\n".join(lines)


def render_ai_analysis(ai):
    lines = [_section("AI Analysis & Recommendations")]

    if ai.get("error"):
        lines.append(f"> ⚠️ AI analysis unavailable: {ai['error']}")
        return "\n".join(lines)

    # Key findings
    findings = ai.get("key_findings", [])
    if findings:
        lines.append(_subsection("Key Findings"))
        for i, f in enumerate(findings, 1):
            emoji = SEVERITY_EMOJI.get(f.get("severity", "info"), "⚪")
            lines.append(f"#### {i}. {emoji} {f.get('title', 'Finding')}")
            lines.append(f"**Severity:** {f.get('severity', 'N/A').upper()}")
            lines.append("")
            lines.append(f.get("description", ""))
            evidence = f.get("evidence", "")
            if evidence:
                lines.append(f"\n> **Evidence:** {evidence}")
            lines.append("")

    # Next steps
    next_steps = ai.get("next_steps", [])
    if next_steps:
        lines.append(_subsection("Recommended Next Steps"))
        for i, step in enumerate(next_steps, 1):
            priority = step.get("priority", "medium").upper()
            tool = step.get("tool_suggestion", "")
            lines.append(f"**{i}. {step.get('step', '')}** `[{priority}]`")
            lines.append(step.get("detail", ""))
            if tool:
                lines.append(f"\n> 🛠️ **Tool:** `{tool}`")
            lines.append("")

    return "\n".join(lines)


def render_risk_indicators(data):
    risks = data.get("risk_indicators", {})
    if not any(risks.values()):
        return ""

    lines = [_section("Risk Indicator Summary")]
    flag_labels = {
        "has_rdp":               ("🔴", "RDP exposed (port 3389)"),
        "has_telnet":            ("🔴", "Telnet exposed (port 23) — unencrypted protocol"),
        "has_ftp":               ("🟠", "FTP exposed (port 21) — unencrypted protocol"),
        "has_smb":               ("🟠", "SMB exposed (port 445) — common attack vector"),
        "has_database_port":     ("🟠", "Database port exposed to network"),
        "has_docker_api":        ("🔴", "Docker API exposed — potential container escape"),
        "has_kubernetes":        ("🔴", "Kubernetes API/kubelet exposed"),
        "missing_hsts":          ("🟡", "HSTS header missing"),
        "missing_csp":           ("🟡", "Content Security Policy missing"),
    }

    found_any = False
    for key, (emoji, label) in flag_labels.items():
        if risks.get(key):
            lines.append(f"- {emoji} {label}")
            found_any = True

    if not found_any:
        return ""

    return "\n".join(lines)


def generate_report(target, aggregated, ai_analysis, output_file):
    """
    Assemble and write the full markdown report.
    Returns the path to the written file.
    """
    sections = [
        render_meta(target, aggregated, ai_analysis),
        _hr(),
        render_executive_summary(ai_analysis),
        _hr(),
        render_risk_indicators(aggregated),
        _hr(),
        render_target_info(aggregated),
        _hr(),
        render_ports(aggregated),
        _hr(),
        render_http(aggregated),
        _hr(),
        render_ssl(aggregated),
        _hr(),
        render_ai_analysis(ai_analysis),
        _hr(),
        "\n_Report generated by **Specter AI** — Attack Surface Intelligence Platform. For authorized use only._\n",
    ]

    report_content = "\n".join(sections)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_content)

    return os.path.abspath(output_file)