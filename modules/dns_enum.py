"""
dns_enum.py — DNS Records & WHOIS Enumeration
Collects A, MX, TXT, NS records and WHOIS registration info.

Sample usage:
    from modules.dns_enum import run_dns_enum
    results = run_dns_enum("example.com")
"""

import socket
from datetime import datetime

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "admin", "portal", "cdn", "status", "app",
]


def resolve_records(domain, record_type, resolver):
    """Resolve a single DNS record type, return list of strings."""
    try:
        answers = resolver.resolve(domain, record_type, lifetime=5)
        results = []
        for rdata in answers:
            if record_type == "MX":
                results.append(f"{rdata.preference} {rdata.exchange}")
            elif record_type == "SOA":
                results.append(f"{rdata.mname} {rdata.rname}")
            else:
                results.append(str(rdata))
        return results
    except (dns.exception.DNSException, Exception):
        return []


def enumerate_subdomains(domain, resolver):
    """Brute-force common subdomain names."""
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A", lifetime=3)
            ips = [str(r) for r in answers]
            found.append({"subdomain": fqdn, "ips": ips})
        except Exception:
            continue
    return found


def get_whois_info(domain):
    """Fetch WHOIS registration data."""
    if not HAS_WHOIS:
        return {"error": "python-whois not installed"}
    try:
        w = whois.whois(domain)
        created = w.creation_date
        expires = w.expiration_date
        # whois sometimes returns a list
        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]
        return {
            "registrar":    str(w.registrar or "N/A"),
            "created":      created.strftime("%Y-%m-%d") if isinstance(created, datetime) else str(created or "N/A"),
            "expires":      expires.strftime("%Y-%m-%d") if isinstance(expires, datetime) else str(expires or "N/A"),
            "name_servers": [str(ns).lower() for ns in (w.name_servers or [])],
            "emails":       list(set(w.emails)) if w.emails else [],
            "country":      str(w.country or "N/A"),
            "org":          str(w.org or w.registrant_name or "N/A"),
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}


def run_dns_enum(domain):
    """
    Main entry point for DNS enumeration.

    Returns dict with keys:
        dns_records, subdomains, whois, ip_addresses
    """
    result = {
        "dns_records":  {},
        "subdomains":   [],
        "whois":        {},
        "ip_addresses": [],
    }

    # ── Basic socket IP resolution (always works) ────────────────────────────
    try:
        infos = socket.getaddrinfo(domain, None)
        result["ip_addresses"] = list({info[4][0] for info in infos})
    except socket.gaierror as e:
        result["ip_addresses"] = []
        result["resolution_error"] = str(e)

    if not HAS_DNSPYTHON:
        result["error"] = "dnspython not installed — install with: pip install dnspython"
        result["whois"] = get_whois_info(domain)
        return result

    # ── DNS records ──────────────────────────────────────────────────────────
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        records = resolve_records(domain, rtype, resolver)
        if records:
            result["dns_records"][rtype] = records

    # ── Subdomain enumeration ────────────────────────────────────────────────
    result["subdomains"] = enumerate_subdomains(domain, resolver)

    # ── WHOIS ────────────────────────────────────────────────────────────────
    result["whois"] = get_whois_info(domain)

    return result