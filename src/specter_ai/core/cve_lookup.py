"""
cve_lookup.py — Known-Vulnerable Version Correlation
Cross-references service banners (port scan banners, HTTP Server headers)
against a small table of well-known CVEs affecting outdated versions of
common services. Intentionally lightweight — not a full nuclei-style
template engine, just a quick, high-signal check on the versions this
tool already fingerprints.

Sample usage:
    from specter_ai.core.cve_lookup import correlate_versions
    matches = correlate_versions(open_ports, server_headers)
"""

import re

VULNERABLE_VERSION_TABLE = [
    {
        "service": "OpenSSH",
        "banner_pattern": r"OpenSSH[_ ]([\d.]+)",
        "fixed_in": (7, 4),
        "cves": ["CVE-2016-10009", "CVE-2016-6210", "CVE-2016-6515"],
        "description": (
            "OpenSSH versions before 7.4 are affected by multiple known issues, "
            "including a ssh-agent privilege escalation (CVE-2016-10009) and "
            "username enumeration via timing (CVE-2016-6210)."
        ),
        "severity": "high",
    },
    {
        "service": "Apache",
        "banner_pattern": r"Apache/([\d.]+)",
        "fixed_in": (2, 4, 18),
        "cves": ["CVE-2017-9798"],
        "description": (
            "Apache HTTP Server versions before 2.4.18 may be affected by the "
            "'Optionsbleed' information disclosure vulnerability (CVE-2017-9798)."
        ),
        "severity": "medium",
    },
    {
        "service": "nginx",
        "banner_pattern": r"nginx/([\d.]+)",
        "fixed_in": (1, 20, 1),
        "cves": ["CVE-2021-23017"],
        "description": (
            "nginx versions before 1.20.1 may be affected by a DNS resolver "
            "off-by-one heap write vulnerability (CVE-2021-23017)."
        ),
        "severity": "high",
    },
    {
        "service": "vsftpd",
        "banner_pattern": r"vsftpd ([\d.]+)",
        "fixed_in": (2, 3, 5),
        "cves": ["CVE-2011-2523"],
        "description": (
            "vsftpd 2.3.4 is known to contain a backdoor allowing unauthenticated "
            "remote command execution (CVE-2011-2523)."
        ),
        "severity": "critical",
    },
    {
        "service": "ProFTPD",
        "banner_pattern": r"ProFTPD ([\d.]+)",
        "fixed_in": (1, 3, 5),
        "cves": ["CVE-2015-3306"],
        "description": (
            "ProFTPD before 1.3.5 mod_copy module allows unauthenticated remote "
            "file copy (CVE-2015-3306)."
        ),
        "severity": "critical",
    },
]


def _parse_version(version_str):
    """Parse a dotted version string into a tuple of ints for comparison."""
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts) if parts else ()


def correlate_versions(open_ports, server_headers=None):
    """
    Cross-reference service banners against VULNERABLE_VERSION_TABLE.

    `open_ports` — list of dicts with a "banner" key (as returned by port_scan)
    `server_headers` — dict possibly containing a "Server" header value

    Returns a list of match dicts: service, version, port, cves, description, severity.
    """
    banners = []
    for p in open_ports or []:
        if p.get("banner"):
            banners.append((p.get("port"), p["banner"]))

    if server_headers and server_headers.get("Server"):
        banners.append((None, server_headers["Server"]))

    matches = []
    for port, banner in banners:
        for entry in VULNERABLE_VERSION_TABLE:
            m = re.search(entry["banner_pattern"], banner)
            if not m:
                continue
            version_tuple = _parse_version(m.group(1))
            if not version_tuple or version_tuple >= entry["fixed_in"]:
                continue
            matches.append({
                "service": entry["service"],
                "version": m.group(1),
                "port": port,
                "cves": entry["cves"],
                "description": entry["description"],
                "severity": entry["severity"],
            })

    return matches
