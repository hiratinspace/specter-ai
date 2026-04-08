"""
aggregator.py — Combines all module outputs into one structured result dict.

Sample usage:
    from core.aggregator import aggregate_results
    data = aggregate_results("example.com", "quick", module_results)
"""

from datetime import datetime, timezone


def aggregate_results(target, mode, module_results):
    """
    Merge all module results into a clean, flat summary dict
    suitable for AI analysis and report generation.
    """
    dns   = module_results.get("dns",   {})
    ports = module_results.get("ports", {})
    http  = module_results.get("http",  {})
    ssl   = module_results.get("ssl",   {})

    # ── Flatten open ports into a clean summary ──────────────────────────────
    open_ports = ports.get("open_ports", [])
    port_summary = [
        {
            "port":    p["port"],
            "service": p.get("service", "unknown"),
            "banner":  p.get("banner"),
        }
        for p in open_ports
    ]

    # ── Collect all SSL findings ─────────────────────────────────────────────
    ssl_findings = ssl.get("findings", [])
    primary_cert = next(
        (c for c in ssl.get("certificates", []) if not c.get("error")),
        None
    )

    # ── Count missing security headers ──────────────────────────────────────
    missing_headers = list(http.get("security_headers_missing", {}).keys())

    # ── Build flat aggregated dict ───────────────────────────────────────────
    aggregated = {
        "meta": {
            "target":     target,
            "scan_mode":  mode,
            "scanned_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        },

        "dns": {
            "ip_addresses":  dns.get("ip_addresses", []),
            "records":       dns.get("dns_records", {}),
            "subdomains":    dns.get("subdomains", []),
            "whois":         dns.get("whois", {}),
        },

        "ports": {
            "target_ip":     ports.get("target_ip", ""),
            "ports_scanned": ports.get("ports_scanned", 0),
            "scan_time_s":   ports.get("scan_time_s", 0),
            "open_ports":    port_summary,
            "open_count":    len(open_ports),
        },

        "http": {
            "status_codes":              http.get("status_codes", {}),
            "redirects":                 http.get("redirects", []),
            "server_headers":            http.get("server_headers", {}),
            "technologies":              http.get("technologies", []),
            "security_headers_present":  list(http.get("security_headers_present", {}).keys()),
            "security_headers_missing":  missing_headers,
            "cookies":                   http.get("cookies", []),
            "response_times_ms":         http.get("response_time_ms", {}),
        },

        "ssl": {
            "certificates": ssl.get("certificates", []),
            "findings":     ssl_findings,
            "http_redirect": ssl.get("http_redirect", {}),
            "primary_cert": {
                "subject":           primary_cert.get("subject", {}) if primary_cert else {},
                "issuer":            primary_cert.get("issuer", {}) if primary_cert else {},
                "protocol":          primary_cert.get("protocol") if primary_cert else None,
                "cipher":            primary_cert.get("cipher") if primary_cert else None,
                "key_bits":          primary_cert.get("key_bits") if primary_cert else None,
                "not_after":         primary_cert.get("not_after") if primary_cert else None,
                "days_until_expiry": primary_cert.get("days_until_expiry") if primary_cert else None,
                "is_expired":        primary_cert.get("is_expired", False) if primary_cert else False,
                "expiring_soon":     primary_cert.get("expiring_soon", False) if primary_cert else False,
                "self_signed":       primary_cert.get("self_signed", False) if primary_cert else False,
                "sans":              primary_cert.get("sans", [])[:10] if primary_cert else [],
            } if primary_cert else None,
        },

        # ── Quick-access risk summary for AI prompt ──────────────────────────
        "risk_indicators": {
            "has_rdp":               any(p["port"] == 3389 for p in open_ports),
            "has_telnet":            any(p["port"] == 23   for p in open_ports),
            "has_ftp":               any(p["port"] == 21   for p in open_ports),
            "has_smb":               any(p["port"] == 445  for p in open_ports),
            "has_database_port":     any(p["port"] in (3306, 5432, 27017, 6379, 1521, 1433) for p in open_ports),
            "has_docker_api":        any(p["port"] in (2375, 2376) for p in open_ports),
            "has_kubernetes":        any(p["port"] in (6443, 10250) for p in open_ports),
            "missing_hsts":          "Strict-Transport-Security" in missing_headers,
            "missing_csp":           "Content-Security-Policy" in missing_headers,
            "ssl_critical_findings": sum(1 for f in ssl_findings if f.get("severity") == "critical"),
            "ssl_high_findings":     sum(1 for f in ssl_findings if f.get("severity") == "high"),
            "subdomains_found":      len(dns.get("subdomains", [])),
        }
    }

    return aggregated