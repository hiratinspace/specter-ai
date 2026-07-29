from http.cookiejar import Cookie

from specter_ai.modules.http_probe import (
    analyze_cookies,
    check_security_headers,
    extract_tech_headers,
    fingerprint_technologies,
)


def test_check_security_headers_splits_present_and_missing():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Server": "nginx",
    }
    present, missing = check_security_headers(headers)
    assert "Strict-Transport-Security" in present
    assert "Content-Security-Policy" in missing
    assert "X-Frame-Options" in missing


def test_extract_tech_headers_only_pulls_known_headers():
    headers = {"Server": "Apache", "X-Powered-By": "PHP/8.2", "Irrelevant-Header": "value"}
    found = extract_tech_headers(headers)
    assert found == {"Server": "Apache", "X-Powered-By": "PHP/8.2"}


def test_fingerprint_technologies_detects_wordpress_from_body():
    headers = {"Server": "Apache"}
    body = "<html><link rel='stylesheet' href='/wp-content/themes/x/style.css'></html>"
    detected = fingerprint_technologies(headers, body)
    assert "WordPress" in detected
    assert "Apache" in detected


def test_fingerprint_technologies_detects_cloudflare_from_server_header():
    # fingerprint_technologies matches against header *values*, not keys —
    # Cloudflare-proxied responses set `Server: cloudflare`.
    headers = {"Server": "cloudflare"}
    detected = fingerprint_technologies(headers, "")
    assert "Cloudflare" in detected


def test_fingerprint_technologies_no_false_positive_on_empty_input():
    assert fingerprint_technologies({}, "") == []


def _make_cookie(secure=False, httponly=False, samesite=None):
    rest = {}
    if httponly:
        rest["HttpOnly"] = None
    if samesite:
        rest["SameSite"] = samesite
    return Cookie(
        version=0, name="session", value="abc", port=None, port_specified=False,
        domain="example.com", domain_specified=False, domain_initial_dot=False,
        path="/", path_specified=True, secure=secure, expires=None, discard=True,
        comment=None, comment_url=None, rest=rest, rfc2109=False,
    )


def test_analyze_cookies_flags_insecure_cookie():
    issues = analyze_cookies([_make_cookie(secure=False, httponly=False)])
    assert len(issues) == 1
    assert set(issues[0]["issues"]) >= {
        "missing Secure flag",
        "missing HttpOnly flag",
        "SameSite not set or None",
    }


def test_analyze_cookies_no_issues_for_well_configured_cookie():
    issues = analyze_cookies([_make_cookie(secure=True, httponly=True, samesite="Strict")])
    assert issues == []
