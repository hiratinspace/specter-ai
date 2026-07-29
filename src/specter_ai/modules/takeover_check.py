"""
takeover_check.py — Subdomain Takeover Detection
Flags subdomains whose CNAME points at a known cloud service that could be
unclaimed (dangling CNAME), a common and high-value recon finding.

Sample usage:
    from specter_ai.modules.takeover_check import check_subdomain_takeover
    finding = check_subdomain_takeover("blog.example.com", resolver)
"""

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# Known cloud services commonly left dangling after a CNAME is created but
# the underlying resource (page, app, bucket) is deleted or never claimed.
# `signature` is text that shows up on the service's "not found/unclaimed"
# page — used as a secondary confidence signal, not required to flag.
TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages",     "cname_suffixes": ["github.io"],
     "signature": "There isn't a GitHub Pages site here"},
    {"service": "Heroku",           "cname_suffixes": ["herokuapp.com", "herokudns.com"],
     "signature": "no such app"},
    {"service": "AWS S3",           "cname_suffixes": ["s3.amazonaws.com", "s3-website"],
     "signature": "NoSuchBucket"},
    {"service": "Azure App Service", "cname_suffixes": ["azurewebsites.net"],
     "signature": "404 Web Site not found"},
    {"service": "Surge.sh",         "cname_suffixes": ["surge.sh"],
     "signature": "project not found"},
    {"service": "Bitbucket Pages",  "cname_suffixes": ["bitbucket.io"],
     "signature": "Repository not found"},
    {"service": "Shopify",          "cname_suffixes": ["myshopify.com"],
     "signature": "Sorry, this shop is currently unavailable"},
    {"service": "WordPress.com",    "cname_suffixes": ["wordpress.com"],
     "signature": "doesn't exist"},
    {"service": "Fastly",           "cname_suffixes": ["fastly.net"],
     "signature": "Fastly error: unknown domain"},
    {"service": "Pantheon",         "cname_suffixes": ["pantheonsite.io"],
     "signature": "The gods are wise"},
    {"service": "Zendesk",          "cname_suffixes": ["zendesk.com"],
     "signature": "Help Center Closed"},
]


def _match_provider(cname_target):
    for provider in TAKEOVER_FINGERPRINTS:
        if any(cname_target.endswith(suffix) for suffix in provider["cname_suffixes"]):
            return provider
    return None


def check_subdomain_takeover(subdomain, resolver, timeout=6):
    """
    Check whether `subdomain` CNAMEs to a known cloud service that could
    indicate a subdomain takeover risk. Returns a finding dict if the
    CNAME target matches a known provider, else None.

    Confidence levels:
        unclaimed_cname_target — CNAME target itself fails to resolve (strong signal)
        signature_matched      — target resolves, but its page shows a known "unclaimed" signature
        check_manually         — target matches a known provider but couldn't be further verified
    """
    try:
        answers = resolver.resolve(subdomain, "CNAME", lifetime=timeout)
        cname_target = str(answers[0].target).rstrip(".").lower()
    except Exception:
        return None

    provider = _match_provider(cname_target)
    if not provider:
        return None

    cname_resolves = True
    try:
        resolver.resolve(cname_target, "A", lifetime=timeout)
    except Exception:
        cname_resolves = False

    if not cname_resolves:
        confidence = "unclaimed_cname_target"
    else:
        confidence = "check_manually"
        if provider.get("signature") and HAS_REQUESTS:
            try:
                resp = requests.get(
                    f"http://{subdomain}",
                    timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (specter-ai security scanner)"},
                )
                if provider["signature"].lower() in resp.text.lower():
                    confidence = "signature_matched"
            except Exception:
                pass

    return {
        "subdomain": subdomain,
        "service": provider["service"],
        "cname_target": cname_target,
        "confidence": confidence,
    }
