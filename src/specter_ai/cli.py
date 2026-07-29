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
from pathlib import Path

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
        epilog=(
            "Examples:\n"
            "  specter-ai --target example.com --mode full --output report.md\n"
            "  specter-ai --targets-file targets.txt --output reports/"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target", "-t",
        help="Target domain or IP (e.g. example.com)"
    )
    target_group.add_argument(
        "--targets-file", "-T",
        help="Path to a file with one target per line (blank lines and #-comments ignored)"
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
        help=(
            "Single-target mode: output filename for the markdown report "
            "(default: <target>_report.md). Batch mode (--targets-file): "
            "output directory for per-target reports (default: current directory)."
        )
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis (useful for offline use or API key not set)"
    )
    return parser.parse_args()


def print_status(msg, symbol="*"):
    print(f"  [{symbol}] {msg}")


def normalize_target(raw_target):
    return raw_target.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")


def read_targets_file(path):
    """Read one target per line from `path`, skipping blank lines and #-comments."""
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def scan_one_target(target, mode, skip_ai, output_file):
    """Run the full scan pipeline for one target and write its report."""
    print_status(f"Target  : {target}")
    print_status(f"Mode    : {mode}")
    print_status(f"Output  : {output_file}")
    if skip_ai:
        print_status("AI analysis skipped (--no-ai flag set)", "!")
    print_status("Starting recon modules...", "→")

    start = time.time()

    def on_module_done(key, label, result, success):
        if success:
            print_status(f"{label} — done", "✓")
        else:
            print_status(f"{label} — failed: {result.get('error')}", "✗")

    print()
    aggregated, ai_analysis = run_scan(
        target,
        mode,
        skip_ai=skip_ai,
        on_module_done=on_module_done,
        on_ai_start=lambda: print_status("Sending findings to Claude for analysis...", "→"),
        on_ai_done=lambda _: print_status("AI analysis — done", "✓"),
    )

    report_path = generate_report(target, aggregated, ai_analysis, output_file)
    elapsed = time.time() - start

    print()
    print_status(f"Scan complete in {elapsed:.1f}s", "✓")
    print_status(f"Report saved to: {report_path}", "✓")
    print()
    return report_path


def run_batch(targets_file, mode, skip_ai, output_dir):
    raw_targets = read_targets_file(targets_file)
    if not raw_targets:
        print_status(f"No targets found in {targets_file}", "!")
        sys.exit(1)

    out_dir = Path(output_dir) if output_dir else Path(".")
    out_dir.mkdir(parents=True, exist_ok=True)

    print_status(f"Batch mode: {len(raw_targets)} target(s) from {targets_file}", "→")

    succeeded, failed = [], []
    for i, raw in enumerate(raw_targets, 1):
        target = normalize_target(raw)
        print()
        print_status(f"[{i}/{len(raw_targets)}] {target}", "=")
        output_file = out_dir / f"{target.replace('.', '_')}_report.md"
        try:
            scan_one_target(target, mode, skip_ai, str(output_file))
            succeeded.append(target)
        except Exception as e:
            print_status(f"Scan failed for {target}: {e}", "✗")
            failed.append(target)

    print()
    print_status(f"Batch complete: {len(succeeded)} succeeded, {len(failed)} failed", "!" if failed else "✓")
    if failed:
        print_status(f"Failed targets: {', '.join(failed)}", "✗")
        sys.exit(1)


def main():
    print(BANNER)
    args = parse_args()

    if args.targets_file:
        run_batch(args.targets_file, args.mode, args.no_ai, args.output)
        return

    target = normalize_target(args.target)
    output_file = args.output or f"{target.replace('.', '_')}_report.md"
    scan_one_target(target, args.mode, args.no_ai, output_file)


def run():
    """Console-script entrypoint (handles Ctrl-C cleanly)."""
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    run()
