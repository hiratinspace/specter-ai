from datetime import timedelta
from http.cookiejar import Cookie
from unittest.mock import patch

from requests.structures import CaseInsensitiveDict

from specter_ai.modules.http_probe import (
    MAX_REDIRECT_HOPS,
    analyze_cookies,
    check_security_headers,
    extract_tech_headers,
    fingerprint_technologies,
    probe_url,
    run_http_probe,
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


# ── Redirect walking (SSRF guard) ─────────────────────────────────────────────
# probe_url follows redirects itself instead of letting `requests` do it, so
# every hop can be safety-checked first. These tests drive that loop through a
# stubbed fetch_once, so no sockets are involved.

class _FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code, location=None, headers=None, body="", elapsed_s=0.05):
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers or {})
        if location:
            self.headers["Location"] = location
        self.text = body
        self.cookies = []
        self.elapsed = timedelta(seconds=elapsed_s)


def _fetcher(responses):
    """
    Build a fetch_once stub plus a log of (url, pinned_ip) it was called with.
    `responses` maps URL → _FakeResponse (or None for unreachable).
    """
    calls = []

    def fake_fetch_once(url, timeout=8, pinned_ip=None):
        calls.append((url, pinned_ip))
        return responses.get(url)

    return fake_fetch_once, calls


SAFE_REDIRECT_TARGET = "https://cdn.example.net/home"
INTERNAL_REDIRECT_TARGET = "http://169.254.169.254/latest/meta-data/"


def test_probe_url_returns_response_directly_when_no_redirect():
    fetch, calls = _fetcher({"https://example.com": _FakeResponse(200, body="hello")})
    with patch("specter_ai.modules.http_probe.fetch_once", fetch):
        resp, chain, not_followed = probe_url("https://example.com", pinned_ip="93.184.216.34")

    assert resp.status_code == 200
    assert chain == ["https://example.com"]
    assert not_followed is None
    assert calls == [("https://example.com", "93.184.216.34")]


def test_probe_url_follows_safe_redirect_and_pins_the_validated_ip():
    fetch, calls = _fetcher({
        "https://example.com": _FakeResponse(302, location=SAFE_REDIRECT_TARGET),
        SAFE_REDIRECT_TARGET: _FakeResponse(200, headers={"Server": "nginx"}),
    })
    with patch("specter_ai.modules.http_probe.fetch_once", fetch), \
         patch("specter_ai.modules.http_probe.is_safe_target",
               return_value=(True, ["203.0.113.9"], None)) as safe_check:
        resp, chain, not_followed = probe_url("https://example.com", pinned_ip="93.184.216.34")

    assert not_followed is None
    assert resp.status_code == 200          # final response, as before
    assert chain == ["https://example.com", SAFE_REDIRECT_TARGET]
    safe_check.assert_called_once_with("cdn.example.net")
    # The new host is connected to at the address that was just validated.
    assert calls[1] == (SAFE_REDIRECT_TARGET, "203.0.113.9")


def test_probe_url_blocks_and_reports_redirect_to_internal_address():
    fetch, calls = _fetcher({
        "https://example.com": _FakeResponse(302, location=INTERNAL_REDIRECT_TARGET),
        INTERNAL_REDIRECT_TARGET: _FakeResponse(200, body="ami-id ..."),
    })
    with patch("specter_ai.modules.http_probe.fetch_once", fetch), \
         patch("specter_ai.modules.http_probe.is_safe_target",
               return_value=(False, ["169.254.169.254"], "private/internal address")):
        resp, chain, not_followed = probe_url("https://example.com", pinned_ip="93.184.216.34")

    # The internal address was never requested...
    assert [url for url, _ip in calls] == ["https://example.com"]
    assert chain == ["https://example.com"]
    assert resp.status_code == 302
    # ...but the attempt is reported rather than silently dropped.
    assert not_followed["to"] == INTERNAL_REDIRECT_TARGET
    assert not_followed["from"] == "https://example.com"
    assert "private/internal address" in not_followed["reason"]


def test_probe_url_same_host_redirect_reuses_pin_without_reresolving():
    fetch, calls = _fetcher({
        "https://example.com": _FakeResponse(301, location="/login"),
        "https://example.com/login": _FakeResponse(200),
    })
    with patch("specter_ai.modules.http_probe.fetch_once", fetch), \
         patch("specter_ai.modules.http_probe.is_safe_target",
               side_effect=AssertionError("same-host hop must not trigger a new lookup")):
        resp, chain, not_followed = probe_url("https://example.com", pinned_ip="93.184.216.34")

    assert not_followed is None
    assert chain == ["https://example.com", "https://example.com/login"]
    # Still pinned to the originally validated address, so the hostname can't
    # be re-resolved to something internal mid-chain.
    assert calls[1] == ("https://example.com/login", "93.184.216.34")
    assert resp.status_code == 200


def test_probe_url_refuses_non_http_redirect_scheme():
    fetch, calls = _fetcher({
        "https://example.com": _FakeResponse(302, location="file:///etc/passwd"),
    })
    with patch("specter_ai.modules.http_probe.fetch_once", fetch):
        _resp, chain, not_followed = probe_url("https://example.com")

    assert len(calls) == 1
    assert chain == ["https://example.com"]
    assert "non-HTTP(S)" in not_followed["reason"]


def test_probe_url_stops_after_hop_cap():
    counter = {"n": 0}

    def endless_redirect(url, timeout=8, pinned_ip=None):
        counter["n"] += 1
        return _FakeResponse(302, location=f"/hop{counter['n']}")

    with patch("specter_ai.modules.http_probe.fetch_once", endless_redirect):
        _resp, chain, not_followed = probe_url("https://example.com")

    assert counter["n"] == MAX_REDIRECT_HOPS + 1  # initial request + capped hops
    assert len(chain) == MAX_REDIRECT_HOPS + 1
    assert f"longer than {MAX_REDIRECT_HOPS} hops" in not_followed["reason"]


def test_probe_url_returns_none_when_target_unreachable():
    fetch, _calls = _fetcher({})  # no response registered → unreachable
    with patch("specter_ai.modules.http_probe.fetch_once", fetch):
        resp, chain, not_followed = probe_url("https://example.com")

    assert resp is None
    assert chain == ["https://example.com"]
    assert not_followed is None


def test_run_http_probe_records_blocked_redirect_and_keeps_normal_fields():
    fetch, calls = _fetcher({
        "https://example.com": _FakeResponse(
            302, location=INTERNAL_REDIRECT_TARGET, headers={"Server": "nginx"}
        ),
        # plain-http attempt is unreachable
    })
    with patch("specter_ai.modules.http_probe.fetch_once", fetch), \
         patch("specter_ai.modules.http_probe.is_safe_target",
               return_value=(False, ["169.254.169.254"], "not allowed")):
        results = run_http_probe("example.com", pinned_ip="93.184.216.34")

    assert len(results["blocked_redirects"]) == 1
    assert results["blocked_redirects"][0]["to"] == INTERNAL_REDIRECT_TARGET
    assert results["status_codes"]["https://example.com"] == 302
    assert results["status_codes"]["http://example.com"] == "unreachable"
    assert results["redirects"] == []                      # nothing was followed
    assert results["server_headers"] == {"Server": "nginx"}
    assert "Content-Security-Policy" in results["security_headers_missing"]
    # Both probes were pinned to the caller-validated address.
    assert [ip for _url, ip in calls] == ["93.184.216.34", "93.184.216.34"]


def test_run_http_probe_records_followed_redirect_chain():
    fetch, _calls = _fetcher({
        "https://example.com": _FakeResponse(301, location=SAFE_REDIRECT_TARGET),
        SAFE_REDIRECT_TARGET: _FakeResponse(200, headers={"Server": "nginx"}, body="wp-content"),
        "http://example.com": _FakeResponse(200),
    })
    with patch("specter_ai.modules.http_probe.fetch_once", fetch), \
         patch("specter_ai.modules.http_probe.is_safe_target",
               return_value=(True, ["203.0.113.9"], None)):
        results = run_http_probe("example.com")

    assert results["blocked_redirects"] == []
    assert results["redirects"] == ["https://example.com", SAFE_REDIRECT_TARGET]
    assert results["status_codes"]["https://example.com"] == 200  # final status
    assert "WordPress" in results["technologies"]
