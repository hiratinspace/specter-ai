"""
Tests for resolve-once / pin-the-IP behaviour.

The web dashboard validates a target with is_safe_target() before the scan
starts; if each module then resolved the hostname again, a low-TTL record could
answer with an internal address the second time around (DNS rebinding). These
tests pin the contract: when a caller supplies `pinned_ip`, the modules connect
to it and do NOT resolve the hostname a second time.
"""

from unittest.mock import MagicMock, patch

import requests
from requests.adapters import HTTPAdapter

from specter_ai.core.pipeline import resolve_once, run_modules_concurrently, run_scan
from specter_ai.core.validation import pick_pinned_ip
from specter_ai.modules.http_probe import PinnedIPHTTPAdapter
from specter_ai.modules.port_scan import run_port_scan
from specter_ai.modules.ssl_check import check_http_redirect, get_cert_info, run_ssl_check

PINNED = "93.184.216.34"


# ── pick_pinned_ip ────────────────────────────────────────────────────────────

def test_pick_pinned_ip_prefers_ipv4_because_the_port_scanner_is_af_inet():
    assert pick_pinned_ip(["2606:2800:220:1:248:1893:25c8:1946", PINNED]) == PINNED


def test_pick_pinned_ip_falls_back_to_ipv6_and_handles_empty():
    assert pick_pinned_ip(["2606:2800::1"]) == "2606:2800::1"
    assert pick_pinned_ip([]) is None


# ── port_scan ─────────────────────────────────────────────────────────────────

def test_run_port_scan_uses_pinned_ip_without_resolving_again():
    with patch("specter_ai.modules.port_scan.socket.gethostbyname") as resolve, \
         patch("specter_ai.modules.port_scan.scan_port", return_value=None):
        results = run_port_scan("example.com", mode="quick", pinned_ip=PINNED)

    resolve.assert_not_called()
    assert results["target_ip"] == PINNED


def test_run_port_scan_still_resolves_when_no_pin_supplied():
    with patch("specter_ai.modules.port_scan.socket.gethostbyname", return_value=PINNED) as resolve, \
         patch("specter_ai.modules.port_scan.scan_port", return_value=None):
        results = run_port_scan("example.com", mode="quick")

    resolve.assert_called_once_with("example.com")
    assert results["target_ip"] == PINNED


def test_run_port_scan_connects_to_the_pinned_address():
    seen = []

    def fake_scan_port(ip, port, timeout=1.5):
        seen.append(ip)
        return None

    with patch("specter_ai.modules.port_scan.scan_port", fake_scan_port):
        run_port_scan("example.com", mode="quick", pinned_ip=PINNED)

    assert set(seen) == {PINNED}


# ── ssl_check ─────────────────────────────────────────────────────────────────

def test_get_cert_info_connects_to_pin_but_keeps_hostname_for_sni():
    cert = {
        "subject":        ((("commonName", "example.com"),),),
        "issuer":         ((("commonName", "Example CA"),),),
        "subjectAltName": (("DNS", "example.com"),),
        "notBefore":      "Jan  1 00:00:00 2030 GMT",
        "notAfter":       "Jan  1 00:00:00 2031 GMT",
    }
    ssock = MagicMock()
    ssock.getpeercert.return_value = cert
    ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    ssock.version.return_value = "TLSv1.3"

    ctx = MagicMock()
    ctx.wrap_socket.return_value.__enter__.return_value = ssock

    with patch("specter_ai.modules.ssl_check.ssl.create_default_context", return_value=ctx), \
         patch("specter_ai.modules.ssl_check.socket.create_connection") as connect:
        info = get_cert_info("example.com", 443, pinned_ip=PINNED)

    # TCP goes to the validated address...
    assert connect.call_args.args[0] == (PINNED, 443)
    # ...while the TLS identity we ask for is still the hostname (SNI + cert).
    assert ctx.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"
    assert info["subject"]["common_name"] == "example.com"


def test_get_cert_info_uses_hostname_when_not_pinned():
    with patch("specter_ai.modules.ssl_check.socket.create_connection",
               side_effect=ConnectionRefusedError) as connect:
        assert get_cert_info("example.com", 8443) is None

    assert connect.call_args.args[0] == ("example.com", 8443)


def test_run_ssl_check_threads_pin_into_every_port_probe():
    with patch("specter_ai.modules.ssl_check.get_cert_info", return_value=None) as cert_info, \
         patch("specter_ai.modules.ssl_check.check_http_redirect",
               return_value={"redirects_to_https": True}) as redirect_check:
        run_ssl_check("example.com", pinned_ip=PINNED)

    assert cert_info.call_count > 1  # one per TLS port
    assert all(c.kwargs["pinned_ip"] == PINNED for c in cert_info.call_args_list)
    assert redirect_check.call_args.kwargs["pinned_ip"] == PINNED


def test_check_http_redirect_requests_the_pin_with_a_host_header():
    opener = MagicMock()
    # ssl_check imports urllib.request lazily inside the function, so patch the
    # stdlib entry point it looks up.
    with patch("urllib.request.build_opener", return_value=opener):
        result = check_http_redirect("example.com", pinned_ip=PINNED)

    req = opener.open.call_args.args[0]
    assert req.host == PINNED                      # connects to the pinned address
    assert req.get_header("Host") == "example.com"  # but asks for the real vhost
    assert result["final_url"] == "http://example.com"


# ── http_probe adapter ────────────────────────────────────────────────────────

def test_pinned_adapter_rewrites_connection_target_only():
    adapter = PinnedIPHTTPAdapter("example.com", PINNED, sni=True)
    prepared = requests.Request("GET", "https://example.com/a?b=1").prepare()

    with patch.object(HTTPAdapter, "send", return_value="sent") as parent_send:
        assert adapter.send(prepared) == "sent"

    sent = parent_send.call_args.args[0]
    assert sent.url == f"https://{PINNED}/a?b=1"      # TCP destination
    assert sent.headers["Host"] == "example.com"      # virtual host preserved
    # SNI stays the hostname, so the server picks the right certificate.
    assert adapter.poolmanager.connection_pool_kw["server_hostname"] == "example.com"
    # The caller's request object is left untouched.
    assert prepared.url == "https://example.com/a?b=1"
    assert "Host" not in prepared.headers


def test_pinned_adapter_leaves_other_hosts_alone():
    adapter = PinnedIPHTTPAdapter("example.com", PINNED, sni=True)
    prepared = requests.Request("GET", "https://cdn.example.net/x").prepare()

    with patch.object(HTTPAdapter, "send", return_value="sent") as parent_send:
        adapter.send(prepared)

    sent = parent_send.call_args.args[0]
    assert sent.url == "https://cdn.example.net/x"
    assert "Host" not in sent.headers


def test_pinned_adapter_keeps_explicit_port_and_brackets_ipv6():
    adapter = PinnedIPHTTPAdapter("example.com", "2606:2800::1", sni=False)
    prepared = requests.Request("GET", "http://example.com:8080/x").prepare()

    with patch.object(HTTPAdapter, "send", return_value="sent") as parent_send:
        adapter.send(prepared)

    sent = parent_send.call_args.args[0]
    assert sent.url == "http://[2606:2800::1]:8080/x"
    assert sent.headers["Host"] == "example.com:8080"
    # No TLS on this adapter, so no server_hostname is forced on the http pool.
    assert "server_hostname" not in adapter.poolmanager.connection_pool_kw


# ── pipeline ──────────────────────────────────────────────────────────────────

def test_resolve_once_passes_through_literal_ips():
    with patch("specter_ai.core.pipeline.socket.gethostbyname") as resolve:
        assert resolve_once("93.184.216.34") == "93.184.216.34"
    resolve.assert_not_called()


def test_resolve_once_returns_none_when_unresolvable():
    with patch("specter_ai.core.pipeline.socket.gethostbyname", side_effect=OSError("nxdomain")):
        assert resolve_once("nope.invalid") is None


def _patched_modules():
    """Patch the four recon modules in the pipeline namespace."""
    return (
        patch("specter_ai.core.pipeline.run_dns_enum", return_value={"dns": True}),
        patch("specter_ai.core.pipeline.run_port_scan", return_value={"ports": True}),
        patch("specter_ai.core.pipeline.run_http_probe", return_value={"http": True}),
        patch("specter_ai.core.pipeline.run_ssl_check", return_value={"ssl": True}),
    )


def test_run_modules_concurrently_pins_connecting_modules_but_not_dns():
    dns_p, ports_p, http_p, ssl_p = _patched_modules()
    with dns_p as dns, ports_p as ports, http_p as http, ssl_p as ssl:
        results = run_modules_concurrently("example.com", "quick", pinned_ip=PINNED)

    assert set(results) == {"dns", "ports", "http", "ssl"}
    assert ports.call_args.kwargs["pinned_ip"] == PINNED
    assert http.call_args.kwargs["pinned_ip"] == PINNED
    assert ssl.call_args.kwargs["pinned_ip"] == PINNED
    # dns_enum must keep querying the real hostname's records.
    dns.assert_called_once_with("example.com")


def test_run_scan_uses_caller_supplied_pin_without_resolving():
    with patch("specter_ai.core.pipeline.socket.gethostbyname") as resolve, \
         patch("specter_ai.core.pipeline.run_modules_concurrently", return_value={}) as run_modules, \
         patch("specter_ai.core.pipeline.aggregate_results", return_value={"aggregated": True}):
        aggregated, ai = run_scan("example.com", skip_ai=True, pinned_ip=PINNED)

    resolve.assert_not_called()
    assert run_modules.call_args.kwargs["pinned_ip"] == PINNED
    assert aggregated == {"aggregated": True}
    assert ai["skipped"] is True


def test_run_scan_resolves_exactly_once_when_no_pin_supplied():
    with patch("specter_ai.core.pipeline.socket.gethostbyname", return_value=PINNED) as resolve, \
         patch("specter_ai.core.pipeline.run_modules_concurrently", return_value={}) as run_modules, \
         patch("specter_ai.core.pipeline.aggregate_results", return_value={}):
        run_scan("example.com", skip_ai=True)

    resolve.assert_called_once_with("example.com")
    assert run_modules.call_args.kwargs["pinned_ip"] == PINNED


def test_run_scan_still_runs_when_target_cannot_be_resolved():
    with patch("specter_ai.core.pipeline.socket.gethostbyname", side_effect=OSError("nxdomain")), \
         patch("specter_ai.core.pipeline.run_modules_concurrently", return_value={}) as run_modules, \
         patch("specter_ai.core.pipeline.aggregate_results", return_value={}):
        run_scan("nope.invalid", skip_ai=True)

    # No pin: modules fall back to their own resolution and report their errors.
    assert run_modules.call_args.kwargs["pinned_ip"] is None
