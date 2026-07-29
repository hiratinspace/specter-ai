from unittest.mock import MagicMock, patch

from specter_ai.modules.takeover_check import check_subdomain_takeover


def _make_resolver(cname_target=None, cname_target_resolves=True):
    resolver = MagicMock()

    def resolve(name, rtype, lifetime=None):
        if rtype == "CNAME":
            if cname_target is None:
                raise Exception("no CNAME record")
            answer = MagicMock()
            answer.target = f"{cname_target}."
            return [answer]
        if rtype == "A":
            if name == cname_target and not cname_target_resolves:
                raise Exception("NXDOMAIN")
            return [MagicMock()]
        raise Exception("unexpected query")

    resolver.resolve.side_effect = resolve
    return resolver


def test_no_cname_returns_none():
    resolver = _make_resolver(cname_target=None)
    assert check_subdomain_takeover("sub.example.com", resolver) is None


def test_cname_to_unrelated_domain_returns_none():
    resolver = _make_resolver(cname_target="internal.example.net")
    assert check_subdomain_takeover("sub.example.com", resolver) is None


def test_cname_to_dangling_github_pages_flags_unclaimed():
    resolver = _make_resolver(cname_target="ghost-org.github.io", cname_target_resolves=False)
    finding = check_subdomain_takeover("sub.example.com", resolver)
    assert finding is not None
    assert finding["service"] == "GitHub Pages"
    assert finding["confidence"] == "unclaimed_cname_target"


def test_cname_resolves_but_no_signature_match_is_check_manually():
    resolver = _make_resolver(cname_target="someapp.herokuapp.com", cname_target_resolves=True)
    with patch("specter_ai.modules.takeover_check.requests.get") as mock_get:
        mock_get.return_value = MagicMock(text="Welcome to my live Heroku app!")
        finding = check_subdomain_takeover("sub.example.com", resolver)
    assert finding is not None
    assert finding["confidence"] == "check_manually"


def test_cname_resolves_with_matching_signature_is_high_confidence():
    resolver = _make_resolver(cname_target="someapp.herokuapp.com", cname_target_resolves=True)
    with patch("specter_ai.modules.takeover_check.requests.get") as mock_get:
        mock_get.return_value = MagicMock(text="Heroku | No such app")
        finding = check_subdomain_takeover("sub.example.com", resolver)
    assert finding is not None
    assert finding["confidence"] == "signature_matched"
