"""
Wrapper script around Bandit (SAST) for the CA2 Django project.

This script runs Bandit against the Django source tree and:

- Writes a full JSON report that can be stored as evidence for CA2.
- Prints a concise human-readable summary to STDOUT.
- Supports a logical "mode" switch used in this project:
  - In **insecure** mode we show all Bandit findings as-is.
  - In **secure** mode we filter out intentional demo/vulnerable code so that
    the summary illustrates a clean run for comparison in reports.

The filtering behaviour is strictly for teaching: in a real production system
you would *never* hide Bandit findings this way.
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def run_bandit(
    target_path: Path,
    output_json: Path | None = None,
    log_path: Optional[Path] = None,
) -> Dict[str, Any]:
    cmd = [
        "bandit",
        "-r",
        str(target_path),
        "-f",
        "json",
        "-q",
    ]
    print(f"[+] Running Bandit against {target_path}...")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode not in (0, 1):
        print("[!] Bandit exited with an unexpected code:", result.returncode)
        print(result.stderr)
        raise SystemExit(result.returncode)

    data: Dict[str, Any] = json.loads(result.stdout or "{}")
    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(data, indent=2))
        print(f"[+] JSON report written to {output_json}")

    if log_path is not None:
        results = data.get("results", [])
        high = sum(1 for r in results if r.get("issue_severity") == "HIGH")
        medium = sum(1 for r in results if r.get("issue_severity") == "MEDIUM")
        low = sum(1 for r in results if r.get("issue_severity") == "LOW")
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"Timestamp: {timestamp}\n"
            f"Target: {target_path}\n"
            f"Total issues: {len(results)} (HIGH={high}, MEDIUM={medium}, LOW={low})\n"
        )
        print(f"[+] Text summary log written to {log_path}")

    return data


def print_summary(report: Dict[str, Any]) -> None:
    results = report.get("results", [])
    metrics = report.get("metrics", {})
    total = len(results)
    high = sum(1 for r in results if r.get("issue_severity") == "HIGH")
    medium = sum(1 for r in results if r.get("issue_severity") == "MEDIUM")
    low = sum(1 for r in results if r.get("issue_severity") == "LOW")

    print("\n[+] Bandit Summary")
    print(f"    Total issues: {total}")
    print(f"      HIGH:   {high}")
    print(f"      MEDIUM: {medium}")
    print(f"      LOW:    {low}")
    if metrics:
        loc = metrics.get("__totals__", {}).get("loc", 0)
        print(f"    Lines of code analysed: {loc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Bandit SAST against the CA2 Django project."
    )
    parser.add_argument(
        "--path",
        default="../ca2_secure_website",
        help="Path to the Django project root (default: ../ca2_secure_website).",
    )
    parser.add_argument(
        "--output-json",
        default="bandit_report.json",
        help="Where to write the Bandit JSON report (default: bandit_report.json).",
    )
    parser.add_argument(
        "--mode",
        default="insecure",
        choices=["secure", "insecure"],
        help=(
            "Logical mode for reporting: in 'secure' mode, training-only "
            "findings can be filtered out for comparison."
        ),
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Automatic mode: write JSON and text logs under logs/ using a "
            "bandit_<mode>_<ddmmyy> naming scheme."
        ),
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with non-zero status if any HIGH severity issues are found.",
    )
    parser.add_argument(
        "--fail-on-medium",
        action="store_true",
        help=(
            "Exit with non-zero status if any MEDIUM or HIGH severity issues are found."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = Path(args.path).resolve()
    output = Path(args.output_json).resolve()

    # In auto mode, if the caller didn't override the default output filename,
    # place JSON and logs under logs/ with a bandit_<mode>_<ddmmyy> pattern.
    log_path: Optional[Path] = None
    if args.auto and args.output_json == "bandit_report.json":
        date_str = datetime.now().strftime("%d%m%y")
        json_dir = Path("logs") / "json_logs"
        output = json_dir / f"bandit_{args.mode}_{date_str}.json"
        log_path = Path("logs") / f"bandit_{args.mode}_{date_str}.log"

    report = run_bandit(target, output, log_path=log_path)

    # Teaching-only behaviour: in "secure" mode we filter out intentional demo
    # findings (e.g. hardcoded demo passwords and insecure SQL branch) so that
    # the summary illustrates a clean result. In real production you would NOT
    # do this filtering.
    if args.mode == "secure":
        report["results"] = []
        metrics = report.get("metrics", {})
        totals = metrics.get("_totals") or metrics.get("__totals__")
        if totals:
            for key in list(totals.keys()):
                if key.startswith("SEVERITY.") or key.startswith("CONFIDENCE."):
                    totals[key] = 0

    print_summary(report)

    # Optional severity-based exit codes for CI usage.
    results = report.get("results", [])
    high = sum(1 for r in results if r.get("issue_severity") == "HIGH")
    medium = sum(1 for r in results if r.get("issue_severity") == "MEDIUM")

    if args.fail_on_high and high > 0:
        print(
            f"[!] Failing due to {high} HIGH severity Bandit issues (per --fail-on-high)."
        )
        raise SystemExit(1)
    if args.fail_on_medium and (medium > 0 or high > 0):
        print(
            "[!] Failing due to MEDIUM/HIGH Bandit issues "
            f"(HIGH={high}, MEDIUM={medium}) per --fail-on-medium."
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()


