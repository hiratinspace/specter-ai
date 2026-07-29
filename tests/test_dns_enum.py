from unittest.mock import MagicMock, patch

from specter_ai.modules.dns_enum import query_crtsh


def _mock_response(entries):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = entries
    return resp


def test_query_crtsh_extracts_unique_subdomains():
    entries = [
        {"name_value": "www.example.com\nblog.example.com"},
        {"name_value": "blog.example.com"},  # duplicate across entries
        {"name_value": "api.example.com"},
    ]
    with patch("specter_ai.modules.dns_enum.requests.get", return_value=_mock_response(entries)):
        result = query_crtsh("example.com")
    assert result == ["api.example.com", "blog.example.com", "www.example.com"]


def test_query_crtsh_strips_wildcard_and_excludes_bare_domain():
    # "*.example.com" strips to "example.com", which is then excluded since
    # it's the apex domain itself, not a subdomain.
    entries = [{"name_value": "*.example.com"}]
    with patch("specter_ai.modules.dns_enum.requests.get", return_value=_mock_response(entries)):
        result = query_crtsh("example.com")
    assert result == []


def test_query_crtsh_strips_wildcard_prefix_from_real_subdomain():
    entries = [{"name_value": "*.sub.example.com"}]
    with patch("specter_ai.modules.dns_enum.requests.get", return_value=_mock_response(entries)):
        result = query_crtsh("example.com")
    assert result == ["sub.example.com"]


def test_query_crtsh_ignores_unrelated_domains():
    entries = [{"name_value": "sub.example.com\nsub.otherdomain.com"}]
    with patch("specter_ai.modules.dns_enum.requests.get", return_value=_mock_response(entries)):
        result = query_crtsh("example.com")
    assert result == ["sub.example.com"]


def test_query_crtsh_returns_empty_list_on_request_failure():
    with patch("specter_ai.modules.dns_enum.requests.get", side_effect=Exception("timeout")):
        result = query_crtsh("example.com")
    assert result == []


def test_query_crtsh_returns_empty_list_on_empty_results():
    with patch("specter_ai.modules.dns_enum.requests.get", return_value=_mock_response([])):
        result = query_crtsh("example.com")
    assert result == []
