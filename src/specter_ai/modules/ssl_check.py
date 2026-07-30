"""
ssl_check.py — SSL/TLS Certificate Inspector
Checks cert validity, expiry, issuer, SANs, and protocol support.

Sample usage:
    from specter_ai.modules.ssl_check import run_ssl_check
    results = run_ssl_check("example.com")
    results = run_ssl_check("example.com", pinned_ip="93.184.216.34")
"""

import ssl
import socket
from datetime import datetime, timezone


# Ports to probe for TLS
TLS_PORTS = [443, 8443, 465, 993, 995]

# Weak/deprecated protocols
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Weak cipher keywords
WEAK_CIPHER_KEYWORDS = [
    "NULL", "EXPORT", "RC4", "DES", "3DES", "MD5", "ANON",
    "ADH", "AECDH", "PSK", "SRP"
]

EXPIRY_WARNING_DAYS = 30


def get_cert_info(hostname, port=443, timeout=8, pinned_ip=None):
    """
    Connect via TLS and extract certificate details.
    Returns dict with certificate metadata.

    `pinned_ip`, when given, is the TCP destination — it replaces a second DNS
    lookup of `hostname`, so we hand the handshake to the address the caller
    already validated. SNI (server_hostname) intentionally stays `hostname`:
    only the route changes, never the TLS identity being inspected.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # intentional — capture even invalid certs

    try:
        with socket.create_connection((pinned_ip or hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                # Parse subject
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))

                # Parse SANs (Subject Alternative Names)
                sans = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    sans.append(f"{san_type}: {san_value}")

                # Parse expiry dates
                not_before_str = cert.get("notBefore", "")
                not_after_str  = cert.get("notAfter",  "")

                fmt = "%b %d %H:%M:%S %Y %Z"
                not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc) if not_before_str else None
                not_after  = datetime.strptime(not_after_str,  fmt).replace(tzinfo=timezone.utc) if not_after_str  else None

                now = datetime.now(tz=timezone.utc)
                days_until_expiry = (not_after - now).days if not_after else None
                is_expired = (days_until_expiry is not None and days_until_expiry < 0)
                expiring_soon = (
                    days_until_expiry is not None and
                    0 <= days_until_expiry <= EXPIRY_WARNING_DAYS
                )

                # Check cipher strength
                cipher_name = cipher[0] if cipher else "unknown"
                weak_cipher = any(kw in cipher_name.upper() for kw in WEAK_CIPHER_KEYWORDS)

                return {
                    "port":            port,
                    "protocol":        protocol,
                    "cipher":          cipher_name,
                    "key_bits":        cipher[2] if cipher else None,
                    "weak_cipher":     weak_cipher,
                    "weak_protocol":   protocol in WEAK_PROTOCOLS if protocol else False,
                    "subject": {
                        "common_name":   subject.get("commonName", "N/A"),
                        "org":           subject.get("organizationName", "N/A"),
                        "country":       subject.get("countryName", "N/A"),
                    },
                    "issuer": {
                        "common_name":   issuer.get("commonName", "N/A"),
                        "org":           issuer.get("organizationName", "N/A"),
                        "country":       issuer.get("countryName", "N/A"),
                    },
                    "sans":              sans[:20],  # cap at 20
                    "not_before":        not_before.strftime("%Y-%m-%d") if not_before else "N/A",
                    "not_after":         not_after.strftime("%Y-%m-%d")  if not_after  else "N/A",
                    "days_until_expiry": days_until_expiry,
                    "is_expired":        is_expired,
                    "expiring_soon":     expiring_soon,
                    "self_signed":       subject == issuer,
                }

    except ssl.SSLCertVerificationError as e:
        return {"port": port, "error": f"SSL verification error: {e}", "weak_protocol": False}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None  # Port not open / TLS not available
    except Exception as e:
        return {"port": port, "error": str(e), "weak_protocol": False}


def check_http_redirect(hostname, timeout=5, pinned_ip=None):
    """
    Check if plain HTTP redirects to HTTPS.

    Redirects are never followed here (only the Location header is inspected),
    and `pinned_ip` — when given — is the connection target, with an explicit
    Host header so the server still answers for `hostname`.
    """
    import urllib.request
    import urllib.error

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    connect_host = pinned_ip or hostname
    if ":" in connect_host:  # IPv6 literal
        connect_host = f"[{connect_host}]"

    try:
        req = urllib.request.Request(
            f"http://{connect_host}",
            headers={"User-Agent": "specter-ai", "Host": hostname},
        )
        opener = urllib.request.build_opener(NoRedirectHandler)
        try:
            opener.open(req, timeout=timeout)
            # Redirects are disabled, so the URL we reached is the one we asked
            # for — report it under the hostname, not the pinned address.
            return {"redirects_to_https": False, "final_url": f"http://{hostname}"}
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "")
            return {"redirects_to_https": loc.startswith("https://"), "location": loc}
    except Exception:
        return {"redirects_to_https": None, "error": "Could not check HTTP redirect"}


def run_ssl_check(target, pinned_ip=None):
    """
    Main entry point for SSL/TLS inspection.

    `pinned_ip` (optional) is an address for `target` the caller already
    resolved and safety-checked; passing it keeps every TLS probe on that one
    address instead of re-resolving `target` once per port. The certificate is
    still requested for `target` itself via SNI.

    Returns dict with keys:
        certificates, findings, http_redirect
    """
    results = {
        "certificates": [],
        "findings":     [],
        "http_redirect": {},
    }

    # ── Probe each TLS port ──────────────────────────────────────────────────
    for port in TLS_PORTS:
        cert_info = get_cert_info(target, port, pinned_ip=pinned_ip)
        if cert_info is None:
            continue  # Port closed or no TLS

        results["certificates"].append(cert_info)

        # ── Flag issues ──────────────────────────────────────────────────────
        if cert_info.get("error"):
            results["findings"].append({
                "severity": "medium",
                "port":     port,
                "finding":  f"SSL error on port {port}: {cert_info['error']}"
            })
            continue

        if cert_info.get("is_expired"):
            results["findings"].append({
                "severity": "critical",
                "port":     port,
                "finding":  f"Certificate EXPIRED {abs(cert_info['days_until_expiry'])} days ago"
            })
        elif cert_info.get("expiring_soon"):
            results["findings"].append({
                "severity": "high",
                "port":     port,
                "finding":  f"Certificate expires in {cert_info['days_until_expiry']} days"
            })

        if cert_info.get("self_signed"):
            results["findings"].append({
                "severity": "medium",
                "port":     port,
                "finding":  "Self-signed certificate — not trusted by browsers"
            })

        if cert_info.get("weak_protocol"):
            results["findings"].append({
                "severity": "high",
                "port":     port,
                "finding":  f"Weak protocol in use: {cert_info.get('protocol')}"
            })

        if cert_info.get("weak_cipher"):
            results["findings"].append({
                "severity": "high",
                "port":     port,
                "finding":  f"Weak cipher suite: {cert_info.get('cipher')}"
            })

    # ── HTTP to HTTPS redirect check ─────────────────────────────────────────
    results["http_redirect"] = check_http_redirect(target, pinned_ip=pinned_ip)
    if results["http_redirect"].get("redirects_to_https") is False:
        results["findings"].append({
            "severity": "medium",
            "port":     80,
            "finding":  "HTTP does not redirect to HTTPS"
        })

    return results