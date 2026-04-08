#!/usr/bin/env python3
"""
SPECTERAI — Attack Surface Intelligence Platform
==================================================
DISCLAIMER: This tool is for AUTHORIZED security testing ONLY.
Do NOT use against systems you do not own or have explicit written
permission to test. Unauthorized scanning is illegal and unethical.
The authors accept no liability for misuse of this tool.
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.dns_enum import run_dns_enum
from modules.port_scan import run_port_scan
from modules.http_probe import run_http_probe
from modules.ssl_check import run_ssl_check
from core.aggregator import aggregate_results
from core.ai_analyst import run_ai_analysis
from report.generator import generate_report

BANNER = r"""
  ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗  █████╗ ██╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║
  ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝███████║██║
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗██╔══██║██║
  ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║██║  ██║██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝

  ATTACK SURFACE INTELLIGENCE  ·v1.0·
  For authorized security testing only.
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="specter-ai: Attack surface intelligence platform",
        epilog="Example: python recon.py --target example.com --mode full --output report.md"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target domain or IP (e.g. example.com)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["quick", "full"],
        default="quick",
        help="Scan mode: quick (top 20 ports) or full (top 1000 ports). Default: quick"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output filename for the markdown report (e.g. report.md). Default: <target>_report.md"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis (useful for offline use or API key not set)"
    )
    return parser.parse_args()


def print_status(msg, symbol="*"):
    print(f"  [{symbol}] {msg}")


def run_modules_concurrently(target, mode):
    """Run all recon modules in parallel using ThreadPoolExecutor."""
    tasks = {
        "dns":  (run_dns_enum,   (target,)),
        "ports":(run_port_scan,  (target, mode)),
        "http": (run_http_probe, (target,)),
        "ssl":  (run_ssl_check,  (target,)),
    }

    results = {}
    labels = {
        "dns":   "DNS / WHOIS enumeration",
        "ports": "Port scanning",
        "http":  "HTTP header analysis",
        "ssl":   "SSL/TLS inspection",
    }

    print()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fn, *args): key
            for key, (fn, args) in tasks.items()
        }
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
                print_status(f"{labels[key]} — done", "✓")
            except Exception as e:
                results[key] = {"error": str(e)}
                print_status(f"{labels[key]} — failed: {e}", "✗")

    return results


def main():
    print(BANNER)

    args = parse_args()
    target = args.target.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
    output_file = args.output or f"{target.replace('.', '_')}_report.md"

    print_status(f"Target  : {target}")
    print_status(f"Mode    : {args.mode}")
    print_status(f"Output  : {output_file}")
    print_status("Starting recon modules...", "→")

    start = time.time()

    # ── Phase 1: Parallel recon ──────────────────────────────────────────────
    module_results = run_modules_concurrently(target, args.mode)

    # ── Phase 2: Aggregate ───────────────────────────────────────────────────
    aggregated = aggregate_results(target, args.mode, module_results)

    # ── Phase 3: AI Analysis ─────────────────────────────────────────────────
    if args.no_ai:
        print_status("AI analysis skipped (--no-ai flag set)", "!")
        ai_analysis = {"skipped": True, "summary": "AI analysis was skipped."}
    else:
        print_status("Sending findings to Claude for analysis...", "→")
        ai_analysis = run_ai_analysis(aggregated)
        print_status("AI analysis — done", "✓")

    # ── Phase 4: Generate report ─────────────────────────────────────────────
    report_path = generate_report(target, aggregated, ai_analysis, output_file)
    elapsed = time.time() - start

    print()
    print_status(f"Scan complete in {elapsed:.1f}s", "✓")
    print_status(f"Report saved to: {report_path}", "✓")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.")
        sys.exit(0)