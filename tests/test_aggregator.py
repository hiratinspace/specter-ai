from specter_ai.core.aggregator import aggregate_results


def make_module_results():
    return {
        "dns": {
            "ip_addresses": ["93.184.216.34"],
            "dns_records": {"A": ["93.184.216.34"]},
            "subdomains": [{"subdomain": "www.example.com", "ips": ["93.184.216.34"]}],
            "whois": {"registrar": "Example Registrar"},
        },
        "ports": {
            "target_ip": "93.184.216.34",
            "ports_scanned": 20,
            "scan_time_s": 1.2,
            "open_ports": [
                {"port": 21, "state": "open", "service": "FTP", "banner": None},
                {"port": 3306, "state": "open", "service": "MySQL", "banner": None},
            ],
        },
        "http": {
            "status_codes": {"https://example.com": 200},
            "redirects": [],
            "server_headers": {"Server": "nginx"},
            "technologies": ["Nginx"],
            "security_headers_present": {},
            "security_headers_missing": {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
            },
            "cookies": [],
            "response_time_ms": {},
        },
        "ssl": {
            "certificates": [],
            "findings": [],
            "http_redirect": {"redirects_to_https": True},
        },
    }


def test_aggregate_flattens_open_ports():
    agg = aggregate_results("example.com", "quick", make_module_results())
    assert agg["ports"]["open_count"] == 2
    assert {p["port"] for p in agg["ports"]["open_ports"]} == {21, 3306}


def test_aggregate_risk_indicators_detect_ftp_and_database_port():
    agg = aggregate_results("example.com", "quick", make_module_results())
    ri = agg["risk_indicators"]
    assert ri["has_ftp"] is True
    assert ri["has_database_port"] is True
    assert ri["has_rdp"] is False


def test_aggregate_missing_headers_flagged():
    agg = aggregate_results("example.com", "quick", make_module_results())
    ri = agg["risk_indicators"]
    assert ri["missing_hsts"] is True
    assert ri["missing_csp"] is True
    assert "Strict-Transport-Security" in agg["http"]["security_headers_missing"]


def test_aggregate_handles_missing_module_results_gracefully():
    agg = aggregate_results("example.com", "quick", {})
    assert agg["ports"]["open_count"] == 0
    assert agg["dns"]["ip_addresses"] == []
    assert agg["ssl"]["primary_cert"] is None
