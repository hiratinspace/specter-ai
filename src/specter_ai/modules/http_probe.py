"""
http_probe.py — HTTP Header Analysis & Tech Detection
Detects server tech, missing security headers, cookies, redirects.

SSRF notes — this module is the only one that follows instructions handed to it
by the scanned host, so two guards live here:
  * Redirects are NOT followed by `requests`. We walk the chain ourselves and
    safety-check every hop first, so a target can't bounce the scanner onto
    127.0.0.1 / RFC1918 / 169.254.169.254 and get the internal response
    written into a public report. A refused hop is reported, not hidden.
  * `pinned_ip` lets the caller supply the address it already validated, so
    the hostname isn't resolved a second time (DNS rebinding). Pinning changes
    only the TCP destination — Host header and TLS SNI keep the real hostname,
    so name-based virtual hosts still serve the site we meant to probe.

Sample usage:
    from specter_ai.modules.http_probe import run_http_probe
    results = run_http_probe("example.com")
    results = run_http_probe("example.com", pinned_ip="93.184.216.34")
"""

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from specter_ai.core.validation import is_safe_target, pick_pinned_ip

try:
    import requests
    import urllib3
    from requests.adapters import HTTPAdapter
    from requests.exceptions import RequestException
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    HTTPAdapter = object  # placeholder so the adapter subclass below still imports

USER_AGENT = "Mozilla/5.0 (specter-ai security scanner)"

# Cap the manual redirect walk. Small on purpose: enough for the ordinary
# http→https→/ hops a real site uses, short enough to bound the work.
MAX_REDIRECT_HOPS = 5

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


class PinnedIPHTTPAdapter(HTTPAdapter):
    """
    Transport adapter that sends requests for `hostname` to `pinned_ip`.

    Only the TCP destination changes: the Host header (and, when `sni=True`,
    the TLS server_name) still carry `hostname`, so virtual hosting and
    certificate selection behave exactly as they would unpinned.

    Deliberately scoped to the Session that mounts it — no patching of
    socket.getaddrinfo or other global state, because the recon modules run
    concurrently in a ThreadPoolExecutor and a process-wide DNS override in
    one thread would corrupt another thread's unrelated lookups.
    """

    def __init__(self, hostname, pinned_ip, sni=False, **kwargs):
        self.hostname = hostname
        self.pinned_ip = pinned_ip
        self.sni = sni
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self.sni:
            # urllib3 hands server_hostname straight to the TLS handshake, so
            # SNI stays the real hostname while the socket goes to pinned_ip.
            kwargs["server_hostname"] = self.hostname
        super().init_poolmanager(*args, **kwargs)

    def send(self, request, **kwargs):
        parts = urlsplit(request.url)
        if parts.hostname and parts.hostname.lower() == (self.hostname or "").lower():
            request = request.copy()
            # Host from hostname[:port], not netloc — netloc could carry userinfo.
            request.headers.setdefault("Host", _netloc(parts.hostname, parts.port))
            request.url = urlunsplit((
                parts.scheme,
                _netloc(self.pinned_ip, parts.port),
                parts.path,
                parts.query,
                parts.fragment,
            ))
        return super().send(request, **kwargs)


def _netloc(host, port=None):
    """Build a URL netloc, bracketing IPv6 literals."""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def _pinned_session(hostname, pinned_ip):
    """
    Session whose connections for `hostname` go to `pinned_ip`.

    Mounted per scheme so the plain-HTTP pool never receives the TLS-only
    server_hostname option.
    """
    session = requests.Session()
    session.mount("https://", PinnedIPHTTPAdapter(hostname, pinned_ip, sni=True))
    session.mount("http://", PinnedIPHTTPAdapter(hostname, pinned_ip, sni=False))
    return session


def fetch_once(url, timeout=8, pinned_ip=None):
    """
    Single HTTP GET that never follows redirects.

    `pinned_ip`, when given, is used as the TCP destination for this URL's
    hostname. Returns the Response, or None if the request failed.
    """
    hostname = urlsplit(url).hostname
    if pinned_ip and hostname:
        session = _pinned_session(hostname, pinned_ip)
    else:
        session = requests.Session()
    try:
        return session.get(
            url,
            timeout=timeout,
            allow_redirects=False,  # hops are validated by probe_url first
            verify=False,  # intentional — cert may be invalid
            headers={"User-Agent": USER_AGENT},
        )
    except RequestException:
        return None
    finally:
        # Body is already buffered (stream=False), so this is safe here.
        session.close()


def _redirect_location(resp):
    """Return the Location a 3xx response points at, or None if not a redirect."""
    location = resp.headers.get("Location")
    if 300 <= resp.status_code < 400 and location:
        return location.strip()
    return None


def probe_url(url, timeout=8, pinned_ip=None, max_hops=MAX_REDIRECT_HOPS):
    """
    Fetch `url`, walking any redirect chain by hand so each hop can be checked
    before it is followed.

    A hop that stays on the same host reuses the connection target we already
    validated. A hop to a different host is resolved and run through
    is_safe_target() first, then pinned to that freshly validated address; if
    it points somewhere internal it is refused and reported.

    Returns (response, chain, not_followed):
        response     — the final response in the chain, or None if unreachable
        chain        — every URL visited, in order (len 1 when no redirect)
        not_followed — {"from", "to", "reason"} for a refused hop, else None
    """
    resp = fetch_once(url, timeout=timeout, pinned_ip=pinned_ip)
    if resp is None:
        return None, [url], None

    chain = [url]
    current_url, current_ip = url, pinned_ip
    current_host = (urlsplit(url).hostname or "").lower()

    for _ in range(max_hops):
        location = _redirect_location(resp)
        if location is None:
            return resp, chain, None

        next_url = urljoin(current_url, location)
        parts = urlsplit(next_url)
        next_host = parts.hostname
        if parts.scheme not in ("http", "https") or not next_host:
            return resp, chain, {
                "from":   current_url,
                "to":     next_url,
                "reason": "Redirect to a non-HTTP(S) URL — not followed",
            }

        if next_host.lower() == current_host:
            # Same host — same already-validated destination, no new lookup.
            next_ip = current_ip
        else:
            safe, resolved_ips, error = is_safe_target(next_host)
            if not safe:
                return resp, chain, {
                    "from":   current_url,
                    "to":     next_url,
                    "reason": error or "Redirect target failed the safety check",
                }
            next_ip = pick_pinned_ip(resolved_ips)

        next_resp = fetch_once(next_url, timeout=timeout, pinned_ip=next_ip)
        if next_resp is None:
            return resp, chain, None  # hop unreachable — report what we have

        chain.append(next_url)
        resp, current_url, current_ip = next_resp, next_url, next_ip
        current_host = next_host.lower()

    location = _redirect_location(resp)
    if location is None:
        return resp, chain, None
    return resp, chain, {
        "from":   current_url,
        "to":     urljoin(current_url, location),
        "reason": f"Redirect chain longer than {max_hops} hops — stopped following",
    }


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


def run_http_probe(target, pinned_ip=None):
    """
    Main entry point for HTTP probing.

    `pinned_ip` (optional) is an address for `target` that the caller already
    resolved and safety-checked; supplying it means this module connects there
    rather than resolving `target` again, which closes the DNS-rebinding window
    between the caller's check and this request. Host header and TLS SNI still
    use `target`, so the probe hits the same virtual host either way.

    Returns dict with keys:
        urls_tried, status_codes, redirects, blocked_redirects, server_headers,
        security_headers_present, security_headers_missing,
        technologies, cookies, response_time_ms
    """
    if not HAS_REQUESTS:
        return {"error": "requests library not installed — run: pip install requests"}

    results = {
        "urls_tried":                [],
        "status_codes":              {},
        "redirects":                 [],
        "blocked_redirects":         [],
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

        resp, chain, not_followed = probe_url(url, pinned_ip=pinned_ip)

        # A target trying to redirect the scanner somewhere internal is itself
        # a finding worth reporting, so record it rather than dropping it.
        if not_followed:
            results["blocked_redirects"].append(not_followed)

        if resp is None:
            results["status_codes"][url] = "unreachable"
            continue

        elapsed_ms = round(resp.elapsed.total_seconds() * 1000, 1)
        results["status_codes"][url]     = resp.status_code
        results["response_time_ms"][url] = elapsed_ms

        # Redirect chain actually walked (initial URL first, final URL last)
        if len(chain) > 1:
            results["redirects"] = chain

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