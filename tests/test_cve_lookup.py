from specter_ai.core.cve_lookup import correlate_versions


def test_flags_old_openssh_banner():
    open_ports = [{"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"}]
    matches = correlate_versions(open_ports)
    assert any(m["service"] == "OpenSSH" and "CVE-2016-10009" in m["cves"] for m in matches)


def test_flags_old_apache_from_server_header():
    matches = correlate_versions([], {"Server": "Apache/2.4.7 (Ubuntu)"})
    assert any(m["service"] == "Apache" and m["version"] == "2.4.7" for m in matches)


def test_does_not_flag_patched_apache():
    matches = correlate_versions([], {"Server": "Apache/2.4.62 (Ubuntu)"})
    assert not any(m["service"] == "Apache" for m in matches)


def test_flags_vsftpd_backdoor_version():
    open_ports = [{"port": 21, "service": "FTP", "banner": "220 (vsftpd 2.3.4)"}]
    matches = correlate_versions(open_ports)
    assert any(m["service"] == "vsftpd" and "CVE-2011-2523" in m["cves"] for m in matches)


def test_no_matches_for_unrelated_banner():
    open_ports = [{"port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK"}]
    matches = correlate_versions(open_ports, {"Server": "nginx/1.25.3"})
    assert matches == []


def test_no_matches_for_empty_input():
    assert correlate_versions([], {}) == []
    assert correlate_versions([], None) == []
