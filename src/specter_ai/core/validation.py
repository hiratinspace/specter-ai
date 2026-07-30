"""
validation.py — Target safety validation (SSRF guard)
Rejects targets that resolve to private, loopback, link-local, reserved,
or multicast addresses, so a public-facing scanner can't be used to probe
internal networks or cloud metadata endpoints (e.g. 169.254.169.254).

Sample usage:
    from specter_ai.core.validation import is_safe_target, pick_pinned_ip
    safe, resolved_ips, error = is_safe_target("example.com")
    pinned_ip = pick_pinned_ip(resolved_ips)
"""

import ipaddress
import socket


def _is_unsafe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_safe_target(target):
    """
    Resolve `target` (domain or literal IP) and check whether any of its
    addresses fall in a private/internal/reserved range.

    Returns (is_safe: bool, resolved_ips: list[str], error: str | None).
    """
    try:
        ipaddress.ip_address(target)
        resolved_ips = [target]
    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None)
            resolved_ips = list({info[4][0] for info in infos})
        except socket.gaierror as e:
            return False, [], f"Could not resolve target: {e}"

    if not resolved_ips:
        return False, [], "Could not resolve target to any IP address"

    unsafe = [ip for ip in resolved_ips if _is_unsafe_ip(ip)]
    if unsafe:
        return (
            False,
            resolved_ips,
            f"Target resolves to a private/internal address ({', '.join(unsafe)}) — not allowed",
        )

    return True, resolved_ips, None


def pick_pinned_ip(resolved_ips):
    """
    Choose which of the validated addresses a scan should pin to, so every
    module connects to the same address that was safety-checked instead of
    re-resolving the hostname (which a low-TTL record could flip underneath us).

    IPv4 is preferred because the port scanner opens AF_INET sockets.
    Returns None if `resolved_ips` is empty.
    """
    for ip in resolved_ips:
        if ":" not in ip:
            return ip
    return resolved_ips[0] if resolved_ips else None
