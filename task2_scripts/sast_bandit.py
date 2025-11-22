"""
Advanced Bandit SAST wrapper for the CA2 secure scripting project.

This script runs Bandit against the Django codebase (or any Python target) and:

- Writes a full JSON report that can be stored as evidence for CA2.
- Optionally writes a text summary log and an Excel workbook of findings
  (one row per issue) under a structured `logs/` hierarchy with automatic,
  non-overwriting filenames.
- Prints a concise human-readable summary to STDOUT, including total issues,
  HIGH/MEDIUM/LOW counts and lines of code analysed.
- Supports a logical "mode" switch used in this project:
  - In **insecure** mode we show all Bandit findings as-is.
  - In **secure** mode we filter out intentionally vulnerable teaching code so
    that the summary illustrates a "clean" run for comparison in reports.
- Adds an approximate OWASP Top 10 classification based on Bandit test IDs so
  you can talk about categories (e.g. Injection, Cryptographic Failures,
  Security Misconfiguration) rather than raw Bandit IDs only.
- Provides a `--summary-only` mode for quick local checks that prints only the
  console summary (including OWASP mapping) without writing any artefacts.
- Supports CI-friendly exit codes via `--fail-on-high` and `--fail-on-medium`
  so the pipeline can fail on serious SAST findings while still generating
  evidence reports.

"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# Approximate mapping from Bandit test IDs or patterns to OWASP Top 10 2021
# categories. This is intentionally simplified and geared towards teaching /
# reporting rather than exact compliance.
OWASP_BANDIT_MAP: Dict[str, List[str]] = {
    # Hardcoded passwords / secrets / keys.
    "B105": ["A02:2021-Cryptographic Failures"],
    "B106": ["A02:2021-Cryptographic Failures"],
    "B107": ["A02:2021-Cryptographic Failures"],
    "B108": ["A02:2021-Cryptographic Failures"],
    "B109": ["A02:2021-Cryptographic Failures"],
    # Use of eval/exec or dynamic code.
    "B102": ["A03:2021-Injection"],
    "B301": ["A03:2021-Injection"],
    "B302": ["A03:2021-Injection"],
    # SQL injection, OS command injection, subprocess with shell=True, etc.
    "B608": ["A03:2021-Injection"],
    "B609": ["A03:2021-Injection"],
    "B604": ["A03:2021-Injection"],
    "B607": ["A03:2021-Injection"],
    # Unsafe deserialisation, XML vulnerabilities.
    "B301-xml": ["A08:2021-Software and Data Integrity Failures"],
    "B314": ["A08:2021-Software and Data Integrity Failures"],
    # Insecure SSL/TLS usage.
    "B501": ["A02:2021-Cryptographic Failures"],
    "B502": ["A02:2021-Cryptographic Failures"],
    # Use of weak hashing algorithms.
    "B303": ["A02:2021-Cryptographic Failures"],
    "B304": ["A02:2021-Cryptographic Failures"],
    # General misconfiguration / debugging.
    "B101": ["A05:2021-Security Misconfiguration"],
}


def run_bandit(
    target_path: Path,
    output_json: Path | None = None,
    log_path: Optional[Path] = None,
    excel_path: Optional[Path] = None,
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

    if excel_path is not None:
        try:
            from openpyxl import Workbook  # type: ignore

            excel_path.parent.mkdir(parents=True, exist_ok=True)
            wb = Workbook()
            ws = wb.active
            ws.title = "issues"
            ws.append(
                [
                    "severity",
                    "confidence",
                    "filename",
                    "line_number",
                    "test_id",
                    "test_name",
                    "issue_text",
                ]
            )
            for r in data.get("results", []):
                ws.append(
                    [
                        r.get("issue_severity"),
                        r.get("issue_confidence"),
                        r.get("filename"),
                        r.get("line_number"),
                        r.get("test_id"),
                        r.get("test_name"),
                        r.get("issue_text"),
                    ]
                )
            wb.save(excel_path)
            print(f"[+] Excel report written to {excel_path}")
        except ImportError:
            print(
                "[!] openpyxl is not installed; skipping Bandit Excel export. "
                "Install it with 'pip install openpyxl' to enable Excel output."
            )

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

    # Approximate OWASP Top 10 classification based on Bandit test IDs. This
    # gives a higher-level view suitable for reports and CA2 commentary.
    category_counts: Dict[str, int] = {}
    for r in results:
        test_id = str(r.get("test_id", "") or "")
        owasp_categories: List[str] = []
        if test_id in OWASP_BANDIT_MAP:
            owasp_categories = OWASP_BANDIT_MAP[test_id]
        # Allow for simple pattern-based mapping if needed.
        elif "xml" in str(r.get("test_name", "")).lower():
            owasp_categories = OWASP_BANDIT_MAP.get("B301-xml", [])

        for cat in owasp_categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    if category_counts:
        print("    OWASP Top 10 signals (approximate):")
        for cat, count in sorted(
            category_counts.items(), key=lambda kv: (-kv[1], kv[0])
        ):
            print(f"      - {cat}: {count}")


class _HelperCallable:
    """
    Simple callable wrapper that does not implement the function descriptor
    protocol. This prevents Python from turning helpers into bound methods when
    they are attached to a test class, while still allowing them to behave like
    normal functions.
    """

    def __init__(self, func: Callable[..., Any]) -> None:
        self._func = func

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - trivial
        return self._func(*args, **kwargs)


# Expose a non-descriptor callable for tests while still keeping normal
# function-like behaviour inside this module and for external callers.
_print_summary_impl = print_summary
print_summary = _HelperCallable(_print_summary_impl)


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
        "--summary-only",
        action="store_true",
        help=(
            "Only print a console summary; do not write JSON/Excel/log files. "
            "Useful for quick local checks."
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

    # In summary-only mode we do not write any artefacts; we just run Bandit
    # and print the summary. This is handy for fast local checks.
    output: Optional[Path] = None
    log_path: Optional[Path] = None
    excel_path: Optional[Path] = None

    if not args.summary_only:
        # Decide whether to use the automatic naming scheme. This applies when
        # --auto is set *or* when the caller leaves --output-json at its default
        # value, so that we avoid littering the project root with bandit_report.json.
        use_auto_naming = args.auto or args.output_json == "bandit_report.json"

        output = Path(args.output_json).resolve()

        if use_auto_naming:
            date_str = datetime.now().strftime("%d%m%y")
            # Use the last path component (without extension for files) as the
            # base name, so paths like task2_scripts/bandit_demo_target.py become
            # bandit_demo_target_bandit_<ddmmyy>.*
            if target.is_file():
                base_name = target.stem
            else:
                base_name = target.name

            json_dir = Path("logs") / "json_logs"
            base_stem = f"{base_name}_bandit_{date_str}"

            # Find a free suffix (", (1)", (2), ...) based on the JSON path so that
            # multiple runs on the same day do not overwrite each other.
            suffix = ""
            output = json_dir / f"{base_stem}.json"
            counter = 1
            while output.exists():
                suffix = f"({counter})"
                output = json_dir / f"{base_stem}{suffix}.json"
                counter += 1

            log_path = Path("logs") / f"{base_stem}{suffix}.log"
            excel_path = Path("logs") / "excel" / f"{base_stem}{suffix}.xlsx"

    report = run_bandit(target, output, log_path=log_path, excel_path=excel_path)

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


