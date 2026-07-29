"""
pipeline.py — Shared scan orchestration used by both the CLI and web dashboard.
Runs all four recon modules concurrently, aggregates results, and optionally
sends them to Claude for analysis. Callers (CLI/web) generate the report file
themselves, since they write to different destinations.

Sample usage:
    from specter_ai.core.pipeline import run_scan
    aggregated, ai_analysis = run_scan("example.com", mode="quick", skip_ai=False)
"""

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


def run_modules_concurrently(target, mode, on_module_start=None, on_module_done=None):
    """
    Run all four recon modules in parallel using ThreadPoolExecutor.

    on_module_start(key, label) fires right before each module is submitted.
    on_module_done(key, label, result, success) fires when each completes.
    """
    tasks = {
        "dns":   (run_dns_enum,   (target,)),
        "ports": (run_port_scan,  (target, mode)),
        "http":  (run_http_probe, (target,)),
        "ssl":   (run_ssl_check,  (target,)),
    }

    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        for key, (fn, args) in tasks.items():
            if on_module_start:
                on_module_start(key, MODULE_LABELS[key])
            futures[executor.submit(fn, *args)] = key

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
    on_module_start=None,
    on_module_done=None,
    on_aggregate_start=None,
    on_ai_start=None,
    on_ai_done=None,
):
    """
    Full scan pipeline: run modules -> aggregate -> (optional) AI analysis.
    Returns (aggregated, ai_analysis).
    """
    module_results = run_modules_concurrently(target, mode, on_module_start, on_module_done)

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
