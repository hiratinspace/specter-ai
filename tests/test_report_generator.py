from pathlib import Path

from specter_ai.report.generator import generate_report


def make_aggregated():
    return {
        "meta": {"target": "example.com", "scan_mode": "quick", "scanned_at": "2026-01-01 00:00 UTC"},
        "dns": {"ip_addresses": ["93.184.216.34"], "records": {}, "subdomains": [], "whois": {}},
        "ports": {
            "target_ip": "93.184.216.34",
            "ports_scanned": 20,
            "scan_time_s": 1.0,
            "open_ports": [],
            "open_count": 0,
        },
        "http": {
            "status_codes": {},
            "redirects": [],
            "server_headers": {},
            "technologies": [],
            "security_headers_present": [],
            "security_headers_missing": [],
            "cookies": [],
            "response_times_ms": {},
        },
        "ssl": {"certificates": [], "findings": [], "http_redirect": {}, "primary_cert": None},
        "risk_indicators": {
            "has_rdp": False, "has_telnet": False, "has_ftp": False, "has_smb": False,
            "has_database_port": False, "has_docker_api": False, "has_kubernetes": False,
            "missing_hsts": False, "missing_csp": False,
            "ssl_critical_findings": 0, "ssl_high_findings": 0, "subdomains_found": 0,
        },
    }


def make_ai_analysis(**overrides):
    base = {
        "executive_summary": "All clear.",
        "risk_level": "low",
        "key_findings": [],
        "next_steps": [],
    }
    base.update(overrides)
    return base


def test_generate_report_writes_file(tmp_path):
    output = tmp_path / "report.md"
    path = generate_report("example.com", make_aggregated(), make_ai_analysis(), str(output))
    assert Path(path).exists()
    content = Path(path).read_text()
    assert "example.com" in content
    assert "Executive Summary" in content


def test_generate_report_includes_risk_badge(tmp_path):
    output = tmp_path / "report.md"
    generate_report("example.com", make_aggregated(), make_ai_analysis(risk_level="critical"), str(output))
    content = output.read_text()
    assert "CRITICAL" in content


def test_generate_report_shows_ai_error(tmp_path):
    output = tmp_path / "report.md"
    generate_report("example.com", make_aggregated(), {"error": "boom"}, str(output))
    content = output.read_text()
    assert "boom" in content


def test_generate_report_lists_open_ports(tmp_path):
    output = tmp_path / "report.md"
    aggregated = make_aggregated()
    aggregated["ports"]["open_ports"] = [{"port": 22, "service": "SSH", "banner": "OpenSSH 9.0"}]
    aggregated["ports"]["open_count"] = 1
    generate_report("example.com", aggregated, make_ai_analysis(), str(output))
    content = output.read_text()
    assert "22" in content
    assert "SSH" in content
