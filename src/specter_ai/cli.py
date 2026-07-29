"""
cli.py — SpecterAI command-line entrypoint
==============================================
DISCLAIMER: This tool is for AUTHORIZED security testing ONLY.
Do NOT use against systems you do not own or have explicit written
permission to test. Unauthorized scanning is illegal and unethical.
The authors accept no liability for misuse of this tool.
"""

import argparse
import sys
import time

from specter_ai.core.pipeline import run_scan
from specter_ai.report.generator import generate_report

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
        epilog="Example: specter-ai --target example.com --mode full --output report.md"
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

    if args.no_ai:
        print_status("AI analysis skipped (--no-ai flag set)", "!")

    def on_module_done(key, label, result, success):
        if success:
            print_status(f"{label} — done", "✓")
        else:
            print_status(f"{label} — failed: {result.get('error')}", "✗")

    print()
    aggregated, ai_analysis = run_scan(
        target,
        args.mode,
        skip_ai=args.no_ai,
        on_module_done=on_module_done,
        on_ai_start=lambda: print_status("Sending findings to Claude for analysis...", "→"),
        on_ai_done=lambda _: print_status("AI analysis — done", "✓"),
    )

    # ── Generate report ──────────────────────────────────────────────────────
    report_path = generate_report(target, aggregated, ai_analysis, output_file)
    elapsed = time.time() - start

    print()
    print_status(f"Scan complete in {elapsed:.1f}s", "✓")
    print_status(f"Report saved to: {report_path}", "✓")
    print()


def run():
    """Console-script entrypoint (handles Ctrl-C cleanly)."""
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    run()
