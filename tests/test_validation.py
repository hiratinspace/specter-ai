from specter_ai.core.validation import is_safe_target


def test_rejects_loopback():
    safe, ips, err = is_safe_target("127.0.0.1")
    assert safe is False
    assert "127.0.0.1" in ips
    assert err is not None


def test_rejects_cloud_metadata_endpoint():
    safe, ips, err = is_safe_target("169.254.169.254")
    assert safe is False
    assert "169.254.169.254" in ips
    assert err is not None


def test_rejects_private_ranges():
    for target in ("10.0.0.5", "172.16.0.1", "192.168.1.1"):
        safe, _, _ = is_safe_target(target)
        assert safe is False, f"{target} should be rejected"


def test_rejects_unresolvable_domain():
    safe, ips, err = is_safe_target("this-domain-should-not-exist-12345.invalid")
    assert safe is False
    assert ips == []
    assert err is not None


def test_allows_public_ip():
    safe, ips, err = is_safe_target("8.8.8.8")
    assert safe is True
    assert ips == ["8.8.8.8"]
    assert err is None
