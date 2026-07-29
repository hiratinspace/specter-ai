"""
dns_enum.py — DNS Records & WHOIS Enumeration
Collects A, MX, TXT, NS records and WHOIS registration info.

Sample usage:
    from specter_ai.modules.dns_enum import run_dns_enum
    results = run_dns_enum("example.com")
"""

import socket
from datetime import datetime

from specter_ai.modules.takeover_check import check_subdomain_takeover

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

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "admin", "portal", "cdn", "status", "app",
]

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 8
MAX_CT_SUBDOMAINS_TO_RESOLVE = 50
MAX_TAKEOVER_CHECKS = 50


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
            found.append({"subdomain": fqdn, "ips": ips, "source": "bruteforce"})
        except Exception:
            continue
    return found


def query_crtsh(domain, timeout=CRTSH_TIMEOUT):
    """
    Query crt.sh (Certificate Transparency logs) for subdomains — passive,
    no direct interaction with the target. Returns a sorted list of unique
    subdomain names, or [] on any failure (rate-limited, down, no results).
    """
    if not HAS_REQUESTS:
        return []
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (specter-ai security scanner)"},
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception:
        return []

    found = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                found.add(name)
    return sorted(found)


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
        dns_records, subdomains, whois, ip_addresses, takeover_risks
    """
    result = {
        "dns_records":    {},
        "subdomains":     [],
        "whois":          {},
        "ip_addresses":   [],
        "takeover_risks": [],
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

    # ── Subdomain enumeration: brute-force + passive CT-log discovery ───────
    result["subdomains"] = enumerate_subdomains(domain, resolver)

    known = {s["subdomain"] for s in result["subdomains"]}
    ct_subdomains = [s for s in query_crtsh(domain) if s not in known]
    result["ct_subdomains_truncated"] = len(ct_subdomains) > MAX_CT_SUBDOMAINS_TO_RESOLVE

    for sub in ct_subdomains[:MAX_CT_SUBDOMAINS_TO_RESOLVE]:
        try:
            answers = resolver.resolve(sub, "A", lifetime=3)
            ips = [str(r) for r in answers]
            result["subdomains"].append({"subdomain": sub, "ips": ips, "source": "ct_log"})
        except Exception:
            continue

    # ── Subdomain takeover check (dangling CNAME to a known cloud service) ──
    for entry in result["subdomains"][:MAX_TAKEOVER_CHECKS]:
        finding = check_subdomain_takeover(entry["subdomain"], resolver)
        if finding:
            result["takeover_risks"].append(finding)

    # ── WHOIS ────────────────────────────────────────────────────────────────
    result["whois"] = get_whois_info(domain)

    return result