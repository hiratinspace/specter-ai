"""
http_probe.py — HTTP Header Analysis & Tech Detection
Detects server tech, missing security headers, cookies, redirects.

Sample usage:
    from modules.http_probe import run_http_probe
    results = run_http_probe("example.com")
"""

import re
try:
    import requests
    import urllib3
    from requests.exceptions import RequestException
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Security headers we expect to find (header → description)
SECURITY_HEADERS = {
    "Strict-Transport-Security":     "HSTS — forces HTTPS connections",
    "Content-Security-Policy":       "CSP — mitigates XSS and injection attacks",
    "X-Frame-Options":               "Clickjacking protection",
    "X-Content-Type-Options":        "MIME sniffing protection",
    "Referrer-Policy":               "Controls referrer info leakage",
    "Permissions-Policy":            "Controls browser feature access",
    "X-XSS-Protection":              "Legacy XSS filter (older browsers)",
    "Cross-Origin-Embedder-Policy":  "COEP isolation policy",
    "Cross-Origin-Opener-Policy":    "COOP isolation policy",
}

# Headers that reveal technology stack
TECH_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-WordPress-Cache", "Via",
    "X-Varnish", "X-Cache", "CF-Ray", "X-Amz-Request-Id",
]

# Regex patterns to detect tech from body/headers
TECH_FINGERPRINTS = {
    "WordPress":    [r"wp-content", r"wp-includes", r"WordPress"],
    "Drupal":       [r"Drupal", r"/sites/default/files/"],
    "Joomla":       [r"/components/com_", r"Joomla"],
    "Laravel":      [r"laravel_session", r"XSRF-TOKEN"],
    "Django":       [r"csrfmiddlewaretoken", r"django"],
    "React":        [r"_react", r"__REACT", r"react-root"],
    "Angular":      [r"ng-version", r"_angular"],
    "jQuery":       [r"jquery", r"jQuery"],
    "Bootstrap":    [r"bootstrap\.css", r"bootstrap\.min"],
    "Cloudflare":   [r"cloudflare", r"CF-Ray"],
    "AWS":          [r"amazonaws\.com", r"aws-", r"AmazonS3"],
    "Nginx":        [r"nginx"],
    "Apache":       [r"Apache"],
    "IIS":          [r"Microsoft-IIS", r"ASP\.NET"],
    "PHP":          [r"X-Powered-By: PHP", r"PHPSESSID"],
    "Node.js":      [r"X-Powered-By: Express", r"Node\.js"],
}


def probe_url(url, timeout=8):
    """Send HTTP request and return response metadata."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,  # intentional — cert may be invalid
            headers={"User-Agent": "Mozilla/5.0 (specter-ai security scanner)"}
        )
        return resp
    except RequestException:
        return None


def extract_tech_headers(headers):
    """Pull interesting technology-revealing headers."""
    found = {}
    for h in TECH_HEADERS:
        val = headers.get(h)
        if val:
            found[h] = val
    return found


def check_security_headers(headers):
    """Return present and missing security headers."""
    present = {}
    missing = {}
    for header, description in SECURITY_HEADERS.items():
        val = headers.get(header)
        if val:
            present[header] = val
        else:
            missing[header] = description
    return present, missing


def fingerprint_technologies(headers, body_text):
    """Detect tech stack from headers and HTML body."""
    detected = []
    combined = " ".join(str(v) for v in headers.values()) + " " + (body_text or "")
    for tech, patterns in TECH_FINGERPRINTS.items():
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                detected.append(tech)
                break
    return list(set(detected))


def analyze_cookies(cookies):
    """Check cookies for security flags."""
    issues = []
    for cookie in cookies:
        flags = []
        if not cookie.secure:
            flags.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("missing HttpOnly flag")
        samesite = cookie._rest.get("SameSite", "").lower()
        if samesite not in ("strict", "lax"):
            flags.append("SameSite not set or None")
        if flags:
            issues.append({"name": cookie.name, "issues": flags})
    return issues


def run_http_probe(target):
    """
    Main entry point for HTTP probing.

    Returns dict with keys:
        urls_tried, status_codes, redirects, server_headers,
        security_headers_present, security_headers_missing,
        technologies, cookies, response_time_ms
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not installed — run: pip install requests"}

    results = {
        "urls_tried":                [],
        "status_codes":              {},
        "redirects":                 [],
        "server_headers":            {},
        "security_headers_present":  {},
        "security_headers_missing":  {},
        "technologies":              [],
        "cookies":                   [],
        "response_time_ms":          {},
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        results["urls_tried"].append(url)

        resp = probe_url(url)
        if resp is None:
            results["status_codes"][url] = "unreachable"
            continue

        elapsed_ms = round(resp.elapsed.total_seconds() * 1000, 1)
        results["status_codes"][url]     = resp.status_code
        results["response_time_ms"][url] = elapsed_ms

        # Follow redirect chain
        if resp.history:
            results["redirects"] = [r.url for r in resp.history] + [resp.url]

        # Tech headers
        results["server_headers"].update(extract_tech_headers(dict(resp.headers)))

        # Security headers
        present, missing = check_security_headers(dict(resp.headers))
        results["security_headers_present"].update(present)
        results["security_headers_missing"].update(missing)

        # Tech fingerprinting
        body_snippet = resp.text[:8000] if resp.text else ""
        techs = fingerprint_technologies(dict(resp.headers), body_snippet)
        results["technologies"] = list(set(results["technologies"] + techs))

        # Cookies
        cookie_issues = analyze_cookies(resp.cookies)
        if cookie_issues:
            results["cookies"] = cookie_issues

    return results