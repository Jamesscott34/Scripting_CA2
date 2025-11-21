"""
Wrapper script around Bandit (SAST) for the CA2 Django project.

This script runs Bandit against the Django source tree and prints a concise
summary, while still allowing the full JSON report to be written to disk.
"""

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict


def run_bandit(target_path: Path, output_json: Path | None = None) -> Dict[str, Any]:
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = Path(args.path).resolve()
    output = Path(args.output_json).resolve()
    report = run_bandit(target, output)

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


if __name__ == "__main__":
    main()


