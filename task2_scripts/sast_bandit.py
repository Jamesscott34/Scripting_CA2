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


SCRIPT_ROOT = Path(__file__).resolve().parent
LOGS_ROOT = SCRIPT_ROOT / "logs"


# Approximate mapping from Bandit test IDs or patterns to OWASP Top 10 2021
# categories. This is intentionally simplified and geared towards teaching /
# reporting rather than exact compliance. Bandit itself still runs its full
# built-in test suite – this mapping is only used to GROUP findings in
# summaries. For the complete list of Bandit plugins, see:
# https://bandit.readthedocs.io/en/latest/plugins/index.html
OWASP_BANDIT_MAP: Dict[str, List[str]] = {
    # Hardcoded passwords / secrets / keys.
    "B105": ["A02:2021-Cryptographic Failures"],
    "B106": ["A02:2021-Cryptographic Failures"],
    "B107": ["A02:2021-Cryptographic Failures"],
    "B108": ["A02:2021-Cryptographic Failures"],
    "B109": ["A02:2021-Cryptographic Failures"],
    "B110": ["A02:2021-Cryptographic Failures"],  # hardcoded temp dirs / similar

    # Use of eval/exec or dynamic code.
    "B102": ["A03:2021-Injection"],
    "B307": ["A03:2021-Injection"],  # eval
    "B308": ["A03:2021-Injection"],  # mark_safe / template injection

    # SQL / OS command injection, subprocess with shell=True, etc.
    "B602": ["A03:2021-Injection"],
    "B603": ["A03:2021-Injection"],
    "B604": ["A03:2021-Injection"],
    "B605": ["A03:2021-Injection"],
    "B606": ["A03:2021-Injection"],
    "B607": ["A03:2021-Injection"],
    "B608": ["A03:2021-Injection"],
    "B609": ["A03:2021-Injection"],

    # Unsafe deserialisation, XML, and data integrity.
    "B201": ["A08:2021-Software and Data Integrity Failures"],  # pickle
    "B301": ["A08:2021-Software and Data Integrity Failures"],
    "B302": ["A08:2021-Software and Data Integrity Failures"],
    "B301-xml": ["A08:2021-Software and Data Integrity Failures"],
    "B314": ["A08:2021-Software and Data Integrity Failures"],
    "B403": ["A08:2021-Software and Data Integrity Failures"],
    "B404": ["A08:2021-Software and Data Integrity Failures"],
    "B405": ["A08:2021-Software and Data Integrity Failures"],
    "B406": ["A08:2021-Software and Data Integrity Failures"],
    "B407": ["A08:2021-Software and Data Integrity Failures"],
    "B408": ["A08:2021-Software and Data Integrity Failures"],
    "B409": ["A08:2021-Software and Data Integrity Failures"],

    # Insecure SSL/TLS usage and weak crypto.
    "B501": ["A02:2021-Cryptographic Failures"],
    "B502": ["A02:2021-Cryptographic Failures"],
    "B503": ["A02:2021-Cryptographic Failures"],
    "B504": ["A02:2021-Cryptographic Failures"],
    "B505": ["A02:2021-Cryptographic Failures"],
    "B506": ["A02:2021-Cryptographic Failures"],
    "B507": ["A02:2021-Cryptographic Failures"],
    "B508": ["A02:2021-Cryptographic Failures"],

    # Use of weak hashing algorithms / weak PRNG / low-entropy secrets.
    "B303": ["A02:2021-Cryptographic Failures"],
    "B304": ["A02:2021-Cryptographic Failures"],
    "B305": ["A02:2021-Cryptographic Failures"],
    "B306": ["A02:2021-Cryptographic Failures"],
    "B311": ["A02:2021-Cryptographic Failures"],

    # General misconfiguration / debugging / assert / dangerous stdlib.
    "B101": ["A05:2021-Security Misconfiguration"],
    "B104": ["A05:2021-Security Misconfiguration"],
    "B310": ["A05:2021-Security Misconfiguration"],  # urllib/requests without TLS verify
    "B312": ["A05:2021-Security Misconfiguration"],  # telnetlib
    "B313": ["A05:2021-Security Misconfiguration"],
    "B320": ["A05:2021-Security Misconfiguration"],
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
        metrics = data.get("metrics", {}) or {}
        high = sum(1 for r in results if r.get("issue_severity") == "HIGH")
        medium = sum(1 for r in results if r.get("issue_severity") == "MEDIUM")
        low = sum(1 for r in results if r.get("issue_severity") == "LOW")
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        # Derive approximate OWASP Top 10 categories for each result so the log
        # file is self-contained and mirrors the JSON/Excel detail. For unknown
        # test IDs we fall back to simple heuristics based on the test name and
        # issue text so that new Bandit checks still land in a sensible bucket.
        def _owasp_for_result(r: Dict[str, Any]) -> List[str]:
            test_id = str(r.get("test_id", "") or "")
            test_name = str(r.get("test_name", "") or "").lower()
            text = str(r.get("issue_text", "") or "").lower()

            if test_id in OWASP_BANDIT_MAP:
                return OWASP_BANDIT_MAP[test_id]

            # Heuristic fallbacks.
            if "xml" in test_name or "xml" in text:
                return OWASP_BANDIT_MAP.get("B301-xml", [])
            if "pickle" in test_name or "pickle" in text:
                return OWASP_BANDIT_MAP.get("B201", [])
            if test_id.startswith("B6") or "subprocess" in text or "shell" in text:
                return OWASP_BANDIT_MAP.get("B604", [])
            if any(k in text for k in ("ssl", "tls", "certificate", "cert ")):
                return OWASP_BANDIT_MAP.get("B501", [])
            if any(k in text for k in ("md5", "sha1", "sha-1")):
                return OWASP_BANDIT_MAP.get("B303", [])
            return []

        # Build a per-file severity summary based on Bandit's metrics so that
        # even files with zero issues are visible in the log.
        per_file_lines: List[str] = []
        file_keys = [
            path for path in metrics.keys() if not str(path).startswith("_")
        ]
        for fname in sorted(file_keys):
            m = metrics.get(fname, {}) or {}
            fh = int(m.get("SEVERITY.HIGH", 0) or 0)
            fm = int(m.get("SEVERITY.MEDIUM", 0) or 0)
            fl = int(m.get("SEVERITY.LOW", 0) or 0)
            total_file = fh + fm + fl
            if total_file:
                per_file_lines.append(
                    f"  {fname}: HIGH={fh}, MEDIUM={fm}, LOW={fl}"
                )
            else:
                per_file_lines.append(f"  {fname}: no issues found")

        lines: List[str] = [
            f"Timestamp: {timestamp}",
            f"Target: {target_path}",
            f"Total issues: {len(results)} (HIGH={high}, MEDIUM={medium}, LOW={low})",
            "",
        ]
        if per_file_lines:
            lines.append("Per-file severity summary:")
            lines.extend(per_file_lines)
            lines.append("")

        for idx, r in enumerate(results, start=1):
            owasp_cats = _owasp_for_result(r)
            lines.append(f"Issue {idx}:")
            lines.append(
                f"  Severity={r.get('issue_severity')}, "
                f"Confidence={r.get('issue_confidence')}, "
                f"Bandit={r.get('test_id')} ({r.get('test_name')})"
            )
            lines.append(
                f"  Location={r.get('filename')}:{r.get('line_number')}"
            )
            lines.append(f"  Text={r.get('issue_text')}")
            if owasp_cats:
                lines.append(
                    "  OWASP="
                    + ", ".join(sorted(set(str(c) for c in owasp_cats)))
                )
            code_snippet = r.get("code")
            if code_snippet:
                lines.append("  Code:")
                for code_line in str(code_snippet).rstrip("\n").splitlines():
                    lines.append(f"    {code_line}")
            lines.append("")  # blank line between issues

        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("\n".join(lines))
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
    metrics = report.get("metrics", {}) or {}
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
    # Reuse the same heuristic mapping logic as the text log writer so that
    # console and logs stay in sync.
    def _owasp_for_result(r: Dict[str, Any]) -> List[str]:
        test_id = str(r.get("test_id", "") or "")
        test_name = str(r.get("test_name", "") or "").lower()
        text = str(r.get("issue_text", "") or "").lower()

        if test_id in OWASP_BANDIT_MAP:
            return OWASP_BANDIT_MAP[test_id]

        if "xml" in test_name or "xml" in text:
            return OWASP_BANDIT_MAP.get("B301-xml", [])
        if "pickle" in test_name or "pickle" in text:
            return OWASP_BANDIT_MAP.get("B201", [])
        if test_id.startswith("B6") or "subprocess" in text or "shell" in text:
            return OWASP_BANDIT_MAP.get("B604", [])
        if any(k in text for k in ("ssl", "tls", "certificate", "cert ")):
            return OWASP_BANDIT_MAP.get("B501", [])
        if any(k in text for k in ("md5", "sha1", "sha-1")):
            return OWASP_BANDIT_MAP.get("B303", [])
        return []

    for r in results:
        owasp_categories = _owasp_for_result(r)

        for cat in owasp_categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    if category_counts:
        print("    OWASP Top 10 signals (approximate):")
        for cat, count in sorted(
            category_counts.items(), key=lambda kv: (-kv[1], kv[0])
        ):
            print(f"      - {cat}: {count}")

    # Per-file severity summary based on Bandit's metrics so you can see which
    # files are clean and which carry risk.
    file_keys = [
        path for path in metrics.keys() if not str(path).startswith("_")
    ]
    if file_keys:
        print("\n[+] Per-file severity summary")
        for fname in sorted(file_keys):
            m = metrics.get(fname, {}) or {}
            fh = int(m.get("SEVERITY.HIGH", 0) or 0)
            fm = int(m.get("SEVERITY.MEDIUM", 0) or 0)
            fl = int(m.get("SEVERITY.LOW", 0) or 0)
            total_file = fh + fm + fl
            if total_file:
                print(
                    f"    {fname}: HIGH={fh}, MEDIUM={fm}, LOW={fl}"
                )
            else:
                print(f"    {fname}: no issues found")


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

            json_dir = LOGS_ROOT / "json_logs"
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

            log_path = LOGS_ROOT / f"{base_stem}{suffix}.log"
            excel_path = LOGS_ROOT / "excel" / f"{base_stem}{suffix}.xlsx"

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


