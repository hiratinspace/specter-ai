"""
pipeline.py — Shared scan orchestration used by both the CLI and web dashboard.
Runs all four recon modules concurrently, aggregates results, and optionally
sends them to Claude for analysis. Callers (CLI/web) generate the report file
themselves, since they write to different destinations.

The target is resolved exactly once per scan and that address is pinned for
every module that opens a connection to it (ports/http/ssl), so a hostname
whose DNS record flips mid-scan can't send those modules somewhere other than
the address the caller checked. Callers that validate the target (the web
dashboard) pass their already-validated IP in as `pinned_ip`; callers that
don't (the trusted local CLI) get the same single-resolution behaviour for
free, just without the safety check.

Sample usage:
    from specter_ai.core.pipeline import run_scan
    aggregated, ai_analysis = run_scan("example.com", mode="quick", skip_ai=False)
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from specter_ai.modules.dns_enum import run_dns_enum
from specter_ai.modules.port_scan import run_port_scan
from specter_ai.modules.http_probe import run_http_probe
from specter_ai.modules.ssl_check import run_ssl_check
from specter_ai.core.aggregator import aggregate_results
from specter_ai.core.ai_analyst import run_ai_analysis

MODULE_LABELS = {
    "dns":   "DNS / WHOIS enumeration",
    "ports": "Port scanning",
    "http":  "HTTP header analysis",
    "ssl":   "SSL/TLS inspection",
}

SKIPPED_AI_ANALYSIS = {
    "skipped": True,
    "executive_summary": "AI analysis skipped.",
    "risk_level": "unknown",
    "key_findings": [],
    "next_steps": [],
}


def resolve_once(target):
    """
    Resolve `target` to the single address the scan will pin to.

    Returns the IP string, or None if it can't be resolved — in which case the
    modules fall back to resolving it themselves and report their own errors,
    exactly as they did before pinning existed.
    """
    try:
        ipaddress.ip_address(target)
        return target  # already a literal address
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except OSError:
        return None


def run_modules_concurrently(target, mode, on_module_start=None, on_module_done=None, pinned_ip=None):
    """
    Run all four recon modules in parallel using ThreadPoolExecutor.

    on_module_start(key, label) fires right before each module is submitted.
    on_module_done(key, label, result, success) fires when each completes.

    `pinned_ip` is handed only to the modules that connect to the target.
    dns_enum is deliberately excluded: its job is to ask resolvers about the
    hostname itself, and it never connects to the resolved address.
    """
    tasks = {
        "dns":   (run_dns_enum,   (target,),      {}),
        "ports": (run_port_scan,  (target, mode), {"pinned_ip": pinned_ip}),
        "http":  (run_http_probe, (target,),      {"pinned_ip": pinned_ip}),
        "ssl":   (run_ssl_check,  (target,),      {"pinned_ip": pinned_ip}),
    }

    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        for key, (fn, args, kwargs) in tasks.items():
            if on_module_start:
                on_module_start(key, MODULE_LABELS[key])
            futures[executor.submit(fn, *args, **kwargs)] = key

        for future in as_completed(futures):
            key = futures[future]
            label = MODULE_LABELS[key]
            try:
                results[key] = future.result()
                if on_module_done:
                    on_module_done(key, label, results[key], True)
            except Exception as e:
                results[key] = {"error": str(e)}
                if on_module_done:
                    on_module_done(key, label, results[key], False)

    return results


def run_scan(
    target,
    mode="quick",
    skip_ai=False,
    pinned_ip=None,
    on_module_start=None,
    on_module_done=None,
    on_aggregate_start=None,
    on_ai_start=None,
    on_ai_done=None,
):
    """
    Full scan pipeline: run modules -> aggregate -> (optional) AI analysis.
    Returns (aggregated, ai_analysis).

    `pinned_ip` is the address every connecting module should use for `target`.
    Public callers that gate on is_safe_target() must pass the IP they
    validated, so the checked address is the connected address. If it's omitted
    we resolve the target once here — no safety check, that's the caller's call
    (the CLI is trusted and may legitimately scan internal hosts) — purely so
    the scan still makes a single lookup instead of one per module.
    """
    if pinned_ip is None:
        pinned_ip = resolve_once(target)

    module_results = run_modules_concurrently(
        target, mode, on_module_start, on_module_done, pinned_ip=pinned_ip
    )

    if on_aggregate_start:
        on_aggregate_start()
    aggregated = aggregate_results(target, mode, module_results)

    if skip_ai:
        ai_analysis = dict(SKIPPED_AI_ANALYSIS)
    else:
        if on_ai_start:
            on_ai_start()
        ai_analysis = run_ai_analysis(aggregated)
        if on_ai_done:
            on_ai_done(ai_analysis)

    return aggregated, ai_analysis
