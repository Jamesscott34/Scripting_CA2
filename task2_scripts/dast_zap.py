"""
OWASP ZAP DAST helper for the CA2 Secure scripting


- Start a ZAP daemon in Docker automatically (or connect to an existing one).
- Perform a quick HEAD pre-check to verify the target is reachable and not in a
  redirect loop before scanning.
- Create a dedicated ZAP context with include/exclude rules for the target.
- Optionally configure form-based authentication and run the spider/active scan
  *as an authenticated user*.
- Run a classic spider followed by an active scan, polling progress at a
  configurable interval.
- Collect all alerts and build:
  - A severity summary (High/Medium/Low/Informational).
  - An approximate OWASP Top 10 mapping based on alert names.
  - A simple impact score and per-rule (pluginId) counts.
- Write results in multiple formats (JSON, HTML, XML, Markdown, Excel, text
  log), plus an optional minimal SARIF report for GitHub Security dashboards.
- Support quality-of-life flags such as:
  - `--ignore-alerts` to drop expected/noisy alerts via regex.
  - `--baseline-json` to compare current vs previous severity counts.
  - `--summary-only` for fast console-only runs without writing artefacts.
  - `--fail-on-high` / `--fail-on-medium` for CI gating by risk level.
"""

import argparse
import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import requests
from zapv2 import ZAPv2


SCRIPT_ROOT = Path(__file__).resolve().parent
LOGS_ROOT = SCRIPT_ROOT / "logs"


# Approximate mapping from common ZAP alert names to OWASP Top 10 2021
# categories. This is intentionally simplified and designed for reporting /
OWASP_ZAP_MAP: Dict[str, List[str]] = {
    # Cross-Site Scripting variants.
    "cross site scripting": ["A03:2021-Injection (XSS)"],
    "xss": ["A03:2021-Injection (XSS)"],
    # SQL injection and injection-style findings.
    "sql injection": ["A03:2021-Injection"],
    "command injection": ["A03:2021-Injection"],
    # Missing or misconfigured security headers / debug settings.
    "x-content-type-options header missing": ["A05:2021-Security Misconfiguration"],
    "x-frame-options header not set": ["A05:2021-Security Misconfiguration"],
    "x-xss-protection header not set": ["A05:2021-Security Misconfiguration"],
    "content-security-policy": ["A05:2021-Security Misconfiguration"],
    "information disclosure": ["A05:2021-Security Misconfiguration"],
    # Authentication / access control issues.
    "authentication": ["A01:2021-Broken Access Control"],
    "authorization": ["A01:2021-Broken Access Control"],
    "directory browsing": ["A01:2021-Broken Access Control"],
    # Sensitive data exposure / weak transport.
    "insecure communication": ["A02:2021-Cryptographic Failures"],
    "insecure cookie": ["A02:2021-Cryptographic Failures"],
}


def _zap_client(api_key: str, host: str, port: int) -> ZAPv2:
    """Create a ZAP client for the given host/port."""

    return ZAPv2(
        apikey=api_key,
        proxies={
            "http": f"http://{host}:{port}",
            "https": f"http://{host}:{port}",
        },
    )


def is_zap_reachable(api_key: str, host: str, port: int) -> bool:
    """Return True if a ZAP daemon appears to be running and responsive."""

    try:
        zap = _zap_client(api_key, host, port)
        # Different versions of the python ZAP client expose ``core.version`` as
        # either a *callable* (method) or a simple property that already
        # contains a string.  In some environments calling it unconditionally
        # (``zap.core.version()``) results in ``TypeError: 'str' object is not
        # callable`` even though the API is actually reachable.
        #
        # To keep this helper robust we support both styles:
        #
        # - If ``zap.core.version`` is callable, invoke it.
        # - Otherwise treat the attribute value as the version string.
        version_attr = zap.core.version  # type: ignore[assignment]
        version = version_attr() if callable(version_attr) else version_attr
        # Any non-empty response here is enough to treat ZAP as "reachable".
        return bool(version)
    except Exception:
        return False


def check_target_available(target: str, insecure: bool) -> bool:
    """
    Perform a quick availability check against the target before scanning.

    This sends a HEAD request and checks for:
    - Reachability (no connection / TLS errors)
    - Reasonable status codes (200/3xx/401/403)
    - No obvious redirect loops
    """
    verify = not insecure

    try:
        resp = requests.head(
            target, timeout=5, allow_redirects=True, verify=verify
        )
    except requests.RequestException as exc:
        print(f"[!] Failed to reach target '{target}': {exc}")
        return False

    if len(resp.history) > 10:
        print(f"[!] Target '{target}' appears to be in a redirect loop.")
        return False

    if resp.status_code not in {200, 301, 302, 401, 403}:
        print(
            f"[!] HEAD {target} returned status {resp.status_code}, "
            "which may indicate the app is not ready for scanning."
        )
        return False

    print(f"[+] Target pre-check OK (status {resp.status_code}).")
    return True


def run_dast(
    target: str,
    api_key: str,
    zap_host: str,
    zap_port: int,
    output_json: Optional[Path] = None,
    output_base: Optional[Path] = None,
    formats: Optional[List[str]] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    auth_users: Optional[List[str]] = None,
    protected_paths: Optional[List[str]] = None,
    enable_rules: Optional[List[str]] = None,
    disable_rules: Optional[List[str]] = None,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    poll_delay: float = 2.0,
    ignore_alerts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run a spider + active scan against the target and return ZAP alerts."""

    zap = _zap_client(api_key, zap_host, zap_port)

    # Create a context so that include/exclude rules and authentication can be
    # scoped cleanly to this target.
    context_name = "ca2-context"
    context_id = zap.context.new_context(context_name)

    # Include rules: default to the target host, plus any user-specified
    # patterns.
    include = include or []
    if not include:
        include.append(f"{target}.*")
    for pattern in include:
        print(f"[+] Including in context: {pattern}")
        zap.context.include_in_context(context_name, pattern)

    # Exclude rules: apply both at the context level and to spider/ascan.
    for pattern in exclude or []:
        print(f"[+] Excluding from context/scan: {pattern}")
        zap.context.exclude_from_context(context_name, pattern)
        zap.spider.exclude_from_scan(pattern)
        zap.ascan.exclude_from_scan(pattern)

    # Optional scan rule tuning: enable/disable specific active scan plugin IDs.
    def _flatten_rule_ids(values: Optional[List[str]]) -> str:
        if not values:
            return ""
        ids: List[str] = []
        for token in values:
            for part in token.split(","):
                part = part.strip()
                if part and part not in ids:
                    ids.append(part)
        return ",".join(ids)

    enable_ids = _flatten_rule_ids(enable_rules)
    disable_ids = _flatten_rule_ids(disable_rules)
    if enable_ids:
        try:
            print(f"[+] Enabling active scan rules (plugin IDs): {enable_ids}")
            zap.ascan.enable_scanners(enable_ids)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[!] Failed to enable rules {enable_ids}: {exc}")
    if disable_ids:
        try:
            print(f"[+] Disabling active scan rules (plugin IDs): {disable_ids}")
            zap.ascan.disable_scanners(disable_ids)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[!] Failed to disable rules {disable_ids}: {exc}")

    # Optional form-based authentication (supporting multiple users/roles).
    user_ids: List[str] = []
    if login_url and (login_username and login_password or auth_users):
        print(f"[+] Configuring form-based authentication via {login_url}...")
        if login_url.startswith("http://") or login_url.startswith("https://"):
            login_full = login_url
        else:
            login_full = target.rstrip("/") + "/" + login_url.lstrip("/")

        auth_method = "formBasedAuthentication"
        login_request_data = "username={%username%}&password={%password%}"
        auth_params = (
            f"loginUrl={login_full}&loginRequestData={login_request_data}"
        )
        zap.authentication.set_authentication_method(
            context_id, auth_method, auth_params
        )
        # Treat any occurrence of "logout" in the response body as a heuristic
        # logged-out indicator; this is simplistic but useful for demos.
        zap.authentication.set_logged_in_indicator(
            context_id, "Logout|logout"
        )

        # Build list of (username, password) pairs.
        credentials: List[tuple[str, str]] = []
        if login_username and login_password:
            credentials.append((login_username, login_password))
        for raw in auth_users or []:
            if ":" not in raw:
                print(
                    f"[!] Skipping invalid auth user '{raw}' "
                    "(expected format username:password)."
                )
                continue
            u, p = raw.split(":", 1)
            u, p = u.strip(), p.strip()
            if not u or not p:
                print(
                    f"[!] Skipping invalid auth user '{raw}' "
                    "(empty username or password)."
                )
                continue
            credentials.append((u, p))

        for idx, (u, p) in enumerate(credentials, start=1):
            user_name = f"ca2-user-{idx}"
            uid = zap.users.new_user(context_id, user_name)
            zap.users.set_credentials(
                context_id,
                uid,
                f"username={u}&password={p}",
            )
            zap.users.set_user_enabled(context_id, uid, "true")
            user_ids.append(uid)

        if user_ids:
            print(f"[+] Authentication configured for {len(user_ids)} user(s): {user_ids}")

    print(f"[+] Accessing target: {target}")
    zap.urlopen(target)

    # Optionally "prime" specific protected paths so they are in scope before
    # spider/active scan (for example, deep account pages or admin URLs).
    for path in protected_paths or []:
        if path.startswith(("http://", "https://")):
            url = path
        else:
            url = target.rstrip("/") + "/" + path.lstrip("/")
        print(f"[+] Priming protected path: {url}")
        try:
            zap.urlopen(url)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[!] Failed to access protected path '{url}': {exc}")

    print("[+] Starting spider...")
    if user_ids:
        for uid in user_ids:
            print(f"[+] Spidering as user id {uid}...")
            scan_id = zap.spider.scan_as_user(context_id, uid, target)
            while int(zap.spider.status(scan_id)) < 100:
                print(f"  - Spider progress (user {uid}): {zap.spider.status(scan_id)}%")
                time.sleep(poll_delay)
    else:
        scan_id = zap.spider.scan(target)
        while int(zap.spider.status(scan_id)) < 100:
            print(f"  - Spider progress: {zap.spider.status(scan_id)}%")
            time.sleep(poll_delay)

    print("[+] Starting active scan...")
    if user_ids:
        for uid in user_ids:
            print(f"[+] Active scan as user id {uid}...")
            active_id = zap.ascan.scan_as_user(context_id, uid, target)
            while int(zap.ascan.status(active_id)) < 100:
                print(f"  - Active scan progress (user {uid}): {zap.ascan.status(active_id)}%")
                time.sleep(poll_delay)
    else:
        active_id = zap.ascan.scan(target)
        while int(zap.ascan.status(active_id)) < 100:
            print(f"  - Active scan progress: {zap.ascan.status(active_id)}%")
            time.sleep(poll_delay)

    raw_alerts = zap.core.alerts()
    # Apply optional regex-based filtering to remove expected/noisy alerts
    # (for example, known benign login failures).
    alerts: List[Dict[str, Any]] = []
    ignore_patterns: List[re.Pattern[str]] = [
        re.compile(pat, re.IGNORECASE) for pat in (ignore_alerts or [])
    ]
    for alert in raw_alerts:
        name = str(alert.get("alert", "") or "")
        if any(p.search(name) for p in ignore_patterns):
            continue
        alerts.append(alert)
    print(f"[+] Scan complete. Total alerts: {len(alerts)}")

    # Basic severity summary and approximate OWASP Top 10 mapping.
    severities: Dict[str, int] = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    category_counts: Dict[str, int] = {}
    rule_counts: Dict[str, int] = {}
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        if risk in severities:
            severities[risk] += 1
        else:
            severities["Informational"] += 1

        # Attach OWASP categories to each alert for reporting. We perform a
        # simple case-insensitive lookup based on the alert name.
        alert_name = str(alert.get("alert", "") or "").lower()
        owasp_categories: List[str] = []
        for key, cats in OWASP_ZAP_MAP.items():
            if key in alert_name:
                owasp_categories.extend(cats)
        # De-duplicate while preserving order.
        unique_cats: List[str] = []
        for cat in owasp_categories:
            if cat not in unique_cats:
                unique_cats.append(cat)

        if unique_cats:
            alert["owasp_categories"] = unique_cats  # type: ignore[assignment]
            for cat in unique_cats:
                category_counts[cat] = category_counts.get(cat, 0) + 1

        plugin_id = str(alert.get("pluginId", "") or "")
        if plugin_id:
            rule_counts[plugin_id] = rule_counts.get(plugin_id, 0) + 1

    # Simple impact score to give a rough sense of risk "mass".
    impact_score = (
        severities["High"] * 9
        + severities["Medium"] * 6
        + severities["Low"] * 3
        + severities["Informational"] * 1
    )

    result: Dict[str, Any] = {
        "target": target,
        "context_id": context_id,
        "user_ids": user_ids,
        "alerts": alerts,
        "severity_summary": severities,
        "owasp_summary": category_counts,
        "rule_summary": rule_counts,
        "impact_score": impact_score,
    }

    # Handle JSON output via legacy --output-json first.
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2))
        print(f"[+] JSON DAST report written to {output_json}")

    # Additional formats driven by --formats/--output-prefix.
    formats = formats or []
    if output_base is not None and formats:
        output_base.parent.mkdir(parents=True, exist_ok=True)
        base = output_base

        if "json" in formats and output_json is None:
            json_path = base.with_suffix(".json")
            json_path.write_text(json.dumps(result, indent=2))
            print(f"[+] JSON DAST report written to {json_path}")

        if "html" in formats:
            html_report = zap.core.htmlreport()
            html_path = base.with_suffix(".html")
            html_path.write_text(html_report)
            print(f"[+] HTML report written to {html_path}")

        if "xml" in formats:
            xml_report = zap.core.xmlreport()
            xml_path = base.with_suffix(".xml")
            xml_path.write_text(xml_report)
            print(f"[+] XML report written to {xml_path}")

        if "md" in formats:
            md_lines: List[str] = [
                f"# ZAP DAST Summary for {target}",
                "",
                "## Scan metadata",
                f"- Target: `{target}`",
                f"- Auth mode: {'authenticated' if user_ids else 'unauthenticated'}",
                f"- Included: {', '.join(include or []) or '(default target host)'}",
                f"- Excluded: {', '.join(exclude or []) or '(none)'}",
                "",
                "## Severity counts",
            ]
            for sev, count in severities.items():
                md_lines.append(f"- **{sev}**: {count}")
            md_lines.append("")
            if category_counts:
                md_lines.append("## OWASP Top 10 signals (approximate)")
                for cat, count in category_counts.items():
                    md_lines.append(f"- **{cat}**: {count}")
                md_lines.append("")
            md_lines.append("## Alerts (top-level summary)")
            for alert in alerts:
                md_lines.append(
                    f"- **{alert.get('risk')}** {alert.get('alert')} "
                    f"on {alert.get('url')}"
                )
            md_path = base.with_suffix(".md")
            md_path.write_text("\n".join(md_lines))
            print(f"[+] Markdown summary written to {md_path}")

        if "xlsx" in formats:
            try:
                from openpyxl import Workbook  # type: ignore

                excel_path = base.with_suffix(".xlsx")
                wb = Workbook()
                ws = wb.active
                ws.title = "alerts"
                ws.append(
                    ["risk", "alert", "url", "param", "evidence"]
                )
                for alert in alerts:
                    ws.append(
                        [
                            alert.get("risk"),
                            alert.get("alert"),
                            alert.get("url"),
                            alert.get("param"),
                            alert.get("evidence"),
                        ]
                    )
                wb.save(excel_path)
                print(f"[+] Excel report written to {excel_path}")
            except ImportError:
                print(
                    "[!] openpyxl is not installed; skipping Excel export for ZAP. "
                    "Install it with 'pip install openpyxl' to enable Excel output."
                )

        # Always emit a simple text log alongside other formats.
        log_path = base.with_suffix(".log")
        log_lines: List[str] = [
            f"ZAP DAST summary for {target}",
            f"Generated at: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
            "",
            "Severity counts:",
        ]
        for sev, count in severities.items():
            log_lines.append(f"  {sev}: {count}")
        log_lines.append("")
        log_lines.append("Alerts:")
        for alert in alerts:
            log_lines.append(
                f"- [{alert.get('risk')}] {alert.get('alert')} on {alert.get('url')}"
            )
        log_path.write_text("\n".join(log_lines))
        print(f"[+] Text log written to {log_path}")

    return result


def run_manual_dast(
    target: str,
    insecure: bool,
    output_json: Optional[Path] = None,
    output_base: Optional[Path] = None,
    formats: Optional[List[str]] = None,
    max_pages: int = 50,
) -> Dict[str, Any]:
    """
    Minimal "manual" DAST fallback when ZAP is not available.

    This does a lightweight crawl of the target using the requests library and
    flags a handful of common issues:
      - Missing security headers (X-Frame-Options, X-Content-Type-Options, CSP)
      - Weak cookies (missing HttpOnly/Secure/SameSite on HTTPS)
      - 5xx responses and obvious error signatures in responses
    """

    print("[*] ZAP is not reachable; running manual HTTP DAST instead...")
    session = requests.Session()
    verify = not insecure

    parsed = urlparse(target)
    base_netloc = parsed.netloc or parsed.path
    start_url = target

    seen: set[str] = set()
    queue: List[str] = [start_url]
    alerts: List[Dict[str, Any]] = []

    security_header_names = [
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "strict-transport-security",
    ]

    error_signatures = [
        "Traceback",
        "Exception",
        "Internal Server Error",
        "500 Internal Server Error",
        "OperationalError",
    ]

    debug_signatures = [
        "Werkzeug Debugger",
        "DEBUG = True",
        "Debug mode",
        "Django Debug",
    ]

    def _add_alert(name: str, risk: str, url: str, evidence: str = "") -> None:
        alerts.append(
            {
                "alert": name,
                "risk": risk,
                "url": url,
                "evidence": evidence,
            }
        )

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        try:
            resp = session.get(url, timeout=5, verify=verify, allow_redirects=True)
        except requests.RequestException as exc:
            _add_alert("Connection error", "Low", url, evidence=str(exc))
            continue

        status = resp.status_code
        text = resp.text or ""
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 5xx / error signatures.
        if 500 <= status < 600:
            _add_alert("Server error (5xx)", "Medium", url, evidence=str(status))
        if any(sig in text for sig in error_signatures):
            _add_alert("Error signature in response body", "Medium", url)

        # Debug / framework information leakage.
        if any(sig in text for sig in debug_signatures):
            _add_alert("Debug information exposed", "Medium", url)

        # Missing security headers.
        missing = [h for h in security_header_names if h not in headers]
        for h in missing:
            if h == "content-security-policy":
                _add_alert("Content Security Policy header missing", "Medium", url)
            elif h == "x-frame-options":
                _add_alert("X-Frame-Options header missing", "Low", url)
            elif h == "x-content-type-options":
                _add_alert("X-Content-Type-Options header missing", "Low", url)
            elif h == "strict-transport-security" and url.startswith("https://"):
                _add_alert("Strict-Transport-Security header missing", "Medium", url)

        # Weak cookies on HTTPS.
        if url.startswith("https://"):
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                if "httponly" not in set_cookie.lower():
                    _add_alert("Cookie missing HttpOnly flag", "Low", url)
                if "secure" not in set_cookie.lower():
                    _add_alert("Cookie missing Secure flag", "Low", url)

        # Simple directory listing detection.
        if "Index of /" in text or "Directory listing for" in text:
            _add_alert("Directory listing enabled", "Low", url)

        # Simple PII / email leak detection.
        if re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, flags=re.IGNORECASE):
            _add_alert("Possible email/PII in response body", "Low", url)

        # Very small HTML link discovery (no external deps).
        if "text/html" in headers.get("content-type", ""):
            for match in re.finditer(r'href=[\'"]([^\'"#]+)', text, flags=re.IGNORECASE):
                href = match.group(1)
                joined = urljoin(url, href)
                parsed_href = urlparse(joined)
                if (
                    parsed_href.scheme in ("http", "https")
                    and (parsed_href.netloc or parsed_href.path) == base_netloc
                    and joined not in seen
                ):
                    queue.append(joined)

    # Build a very small severity summary to keep the shape similar to ZAP.
    severities: Dict[str, int] = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for a in alerts:
        risk = str(a.get("risk", "Informational") or "Informational")
        if risk not in severities:
            risk = "Informational"
        severities[risk] += 1

    # Rough OWASP classification for manual issues.
    owasp_summary: Dict[str, int] = {}
    for a in alerts:
        name = str(a.get("alert", "")).lower()
        cats: List[str] = []
        if "cookie" in name:
            cats.append("A02:2021-Cryptographic Failures")
        if "header" in name or "csp" in name or "x-frame-options" in name:
            cats.append("A05:2021-Security Misconfiguration")
        if "server error" in name or "error signature" in name:
            cats.append("A05:2021-Security Misconfiguration")
        if "debug" in name:
            cats.append("A05:2021-Security Misconfiguration")
        if "directory listing" in name or "listing enabled" in name:
            cats.append("A05:2021-Security Misconfiguration")
        if "pii" in name or "email" in name:
            cats.append("A09:2021-Security Logging and Monitoring Failures")
        for c in cats:
            owasp_summary[c] = owasp_summary.get(c, 0) + 1
        if cats:
            a["owasp_categories"] = cats  # type: ignore[assignment]

    impact_score = (
        severities["High"] * 9
        + severities["Medium"] * 6
        + severities["Low"] * 3
        + severities["Informational"] * 1
    )

    result: Dict[str, Any] = {
        "target": target,
        "alerts": alerts,
        "severity_summary": severities,
        "owasp_summary": owasp_summary,
        "impact_score": impact_score,
        "engine": "manual-http",
        "pages_crawled": len(seen),
    }

    # Basic JSON/text output.
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2))
        print(f"[+] Manual DAST JSON report written to {output_json}")

    formats = formats or []
    if output_base is not None and formats:
        output_base.parent.mkdir(parents=True, exist_ok=True)
        base = output_base

        if "json" in formats and output_json is None:
            json_path = base.with_suffix(".json")
            json_path.write_text(json.dumps(result, indent=2))
            print(f"[+] Manual DAST JSON report written to {json_path}")

        log_path = base.with_suffix(".log")
        lines = [
            f"Manual HTTP DAST summary for {target}",
            f"Generated at: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
            "",
            f"Pages crawled: {len(seen)}",
            "",
            "Severity counts:",
        ]
        for sev, count in severities.items():
            lines.append(f"  {sev}: {count}")
        lines.append("")
        lines.append("Alerts:")
        for a in alerts:
            lines.append(f"- [{a.get('risk')}] {a.get('alert')} on {a.get('url')}")
        log_path.write_text("\n".join(lines))
        print(f"[+] Manual DAST text log written to {log_path}")

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an OWASP ZAP DAST scan against the CA2 Django app or another target."
    )
    parser.add_argument(
        "-t",
        "--target",
        default="http://localhost:8000",
        help="Target URL to scan (default: http://localhost:8000).",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="ZAP API key (if configured).",
    )
    parser.add_argument(
        "--zap-host",
        default="localhost",
        help="ZAP host (default: localhost).",
    )
    parser.add_argument(
        "--zap-port",
        type=int,
        default=8080,
        help="ZAP port (default: 8080).",
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to write a JSON report of all ZAP alerts.",
    )
    parser.add_argument(
        "--type",
        choices=["zap", "dast"],
        default="zap",
        help=(
            "Engine to use: 'zap' (default) to run an OWASP ZAP scan when "
            "available (falling back to manual HTTP checks if not), or 'dast' "
            "to always run the built-in manual HTTP scanner only."
        ),
    )
    parser.add_argument(
        "--login-url",
        default=None,
        help=(
            "Optional login URL or path for form-based authentication, "
            "e.g. /accounts/login/."
        ),
    )
    parser.add_argument(
        "--login-username",
        default=None,
        help="Username to use for ZAP form-based authentication.",
    )
    parser.add_argument(
        "--login-password",
        default=None,
        help="Password to use for ZAP form-based authentication.",
    )
    parser.add_argument(
        "--auth-users",
        nargs="*",
        default=None,
        help=(
            "Additional authenticated users in the form username:password. "
            "Requires --login-url. Example: --auth-users alice:pass bob:secret"
        ),
    )
    parser.add_argument(
        "--include",
        nargs="*",
        default=None,
        help=(
            "Optional regex patterns to include in the ZAP context. "
            "By default the target URL is included."
        ),
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=None,
        help=(
            "Optional regex patterns to exclude from the ZAP context and "
            "from spider/active scans (e.g. '/static/.*' '/admin/.*')."
        ),
    )
    parser.add_argument(
        "--protected-paths",
        nargs="*",
        default=None,
        help=(
            "Optional list of paths or URLs that should be explicitly "
            "requested before scanning, e.g. /transfer/ /admin/."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification when performing pre-checks.",
    )
    parser.add_argument(
        "--output-prefix",
        default=None,
        help=(
            "Optional base path (without extension) for multi-format reports "
            "such as JSON/HTML/XML/Markdown."
        ),
    )
    parser.add_argument(
        "--formats",
        default="json",
        help=(
            "Comma-separated list of additional report formats to write when "
            "used with --output-prefix. Supported: json,html,xml,md. "
            "Default: json."
        ),
    )
    parser.add_argument(
        "--enable-rules",
        nargs="*",
        default=None,
        help=(
            "Optional list of ZAP active scan plugin IDs to enable before "
            "scanning. Example: --enable-rules 40012 40018"
        ),
    )
    parser.add_argument(
        "--disable-rules",
        nargs="*",
        default=None,
        help=(
            "Optional list of ZAP active scan plugin IDs to disable before "
            "scanning. Example: --disable-rules 40025 40029"
        ),
    )
    parser.add_argument(
        "--ignore-alerts",
        nargs="*",
        default=None,
        help=(
            "Optional regex patterns; any alerts whose name matches these "
            "patterns will be excluded from summaries and reports."
        ),
    )
    parser.add_argument(
        "--poll-delay",
        type=float,
        default=2.0,
        help="Delay in seconds between ZAP spider/scan status polls (default: 2.0).",
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with non-zero status if any High risk alerts are found.",
    )
    parser.add_argument(
        "--fail-on-medium",
        action="store_true",
        help=(
            "Exit with non-zero status if any Medium or High risk alerts are found."
        ),
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help=(
            "Only print a console severity summary; do not write JSON/HTML/Excel "
            "reports or text logs. Intended for quick local checks."
        ),
    )
    parser.add_argument(
        "--baseline-json",
        default=None,
        help=(
            "Optional path to a previous ZAP JSON report to compare against. "
            "When provided, a trend summary (diff in High/Medium/Low counts) is "
            "printed after the main summary."
        ),
    )
    parser.add_argument(
        "--sarif-path",
        default=None,
        help=(
            "Optional path to write a minimal SARIF v2.1.0 report derived from "
            "ZAP alerts (useful for GitHub Security dashboards)."
        ),
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help=(
            "Run a full automatic scan with sensible defaults suitable for "
            "CA2 demonstrations (reports under logs/zap_reports, "
            "HTML/JSON/MD outputs, and standard excludes for static/admin paths)."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_json = Path(args.output_json) if args.output_json else None
    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    output_base = Path(args.output_prefix) if args.output_prefix else None
    sarif_path = Path(args.sarif_path) if args.sarif_path else None

    # Auto mode: set a sensible output prefix under logs/zap_reports and
    # default to multiple formats.
    if args.auto:
        # Derive a base name of the form zap_<host>_<ddmmyy> under logs/zap_reports.
        parsed = urlparse(args.target)
        host = parsed.netloc or parsed.path or "target"
        safe_host = host.replace(":", "_").replace(".", "_")
        date_str = datetime.now().strftime("%d%m%y")
        if output_base is None:
            output_base = LOGS_ROOT / "zap_reports" / f"zap_{safe_host}_{date_str}"
        if not formats:
            formats = ["json", "html", "md", "xlsx"]

    # In summary-only mode, we suppress all file outputs and only emit a
    # severity summary to the console.
    if args.summary_only:
        output_json = None
        output_base = None
        formats = []

    # Quick availability check for the target before we start ZAP work.
    if not check_target_available(args.target, insecure=args.insecure):
        return

    # Decide whether to run ZAP, the manual HTTP scanner, or both (fallback).
    if args.type == "zap":
        if is_zap_reachable(args.api_key, args.zap_host, args.zap_port):
            result = run_dast(
                target=args.target,
                api_key=args.api_key,
                zap_host=args.zap_host,
                zap_port=args.zap_port,
                output_json=output_json,
                output_base=output_base,
                formats=formats,
                login_url=args.login_url,
                login_username=args.login_username,
                login_password=args.login_password,
                auth_users=args.auth_users,
                protected_paths=args.protected_paths,
                enable_rules=args.enable_rules,
                disable_rules=args.disable_rules,
                include=args.include,
                exclude=args.exclude,
                poll_delay=args.poll_delay,
                ignore_alerts=args.ignore_alerts,
            )
        else:
            print(
                "[!] No running ZAP daemon detected; falling back to manual HTTP DAST.\n"
                "    To enable full ZAP scanning in future, install and start ZAP:\n"
                "      - Getting started: https://www.zaproxy.org/getting-started\n"
                "      - Download:        https://www.zaproxy.org/download\n"
            )
            result = run_manual_dast(
                target=args.target,
                insecure=args.insecure,
                output_json=output_json,
                output_base=output_base,
                formats=formats,
            )
    else:
        # --type dast: skip ZAP entirely and just run the manual HTTP crawler.
        print("[*] Engine type 'dast' selected; running manual HTTP scanner only.")
        result = run_manual_dast(
            target=args.target,
            insecure=args.insecure,
            output_json=output_json,
            output_base=output_base,
            formats=formats,
        )

    # Print a concise console summary and optionally fail the process based on
    # alert severities (CI-style usage).
    if result is not None:
        severities = result.get("severity_summary", {})
        owasp_summary = result.get("owasp_summary", {}) or {}
        high = int(severities.get("High", 0) or 0)
        medium = int(severities.get("Medium", 0) or 0)

        print("\n[+] ZAP Severity Summary")
        for sev in ("High", "Medium", "Low", "Informational"):
            print(f"    {sev}: {int(severities.get(sev, 0) or 0)}")

        if owasp_summary:
            print("    OWASP Top 10 signals (approximate):")
            for cat, count in sorted(
                owasp_summary.items(), key=lambda kv: (-int(kv[1] or 0), kv[0])
            ):
                print(f"      - {cat}: {int(count or 0)}")

        # Show a few example alerts to give context.
        alerts = result.get("alerts", [])[:5]
        if alerts:
            print("    Sample alerts:")
            for alert in alerts:
                print(
                    f"      - [{alert.get('risk')}] {alert.get('alert')} "
                    f"on {alert.get('url')}"
                )

        # Optional trend comparison against a previous JSON report.
        if args.baseline_json:
            baseline_path = Path(args.baseline_json)
            if baseline_path.exists():
                try:
                    baseline = json.loads(
                        baseline_path.read_text(encoding="utf-8")
                    )
                except json.JSONDecodeError as exc:
                    print(
                        f"[!] Failed to parse baseline ZAP JSON '{baseline_path}': {exc}"
                    )
                else:
                    base_sev = baseline.get("severity_summary", {}) or {}
                    print("\n[+] Trend vs baseline")
                    for level in ("High", "Medium", "Low", "Informational"):
                        curr = int(severities.get(level, 0) or 0)
                        prev = int(base_sev.get(level, 0) or 0)
                        delta = curr - prev
                        sign = "+" if delta > 0 else ""
                        print(
                            f"    {level}: {curr} (baseline {prev}, change {sign}{delta})"
                        )
            else:
                print(
                    f"[!] Baseline ZAP JSON '{baseline_path}' not found; skipping trend comparison."
                )

        if args.fail_on_high and high > 0:
            print(
                f"[!] Failing due to {high} High risk alerts (per --fail-on-high)."
            )
            raise SystemExit(1)
        if args.fail_on_medium and (medium > 0 or high > 0):
            print(
                "[!] Failing due to Medium/High risk alerts "
                f"(High={high}, Medium={medium}) per --fail-on-medium."
            )
            raise SystemExit(1)

        # Optionally emit a minimal SARIF report for CI integration.
        if sarif_path is not None:
            _write_sarif(result, sarif_path)


def _write_sarif(result: Dict[str, Any], sarif_path: Path) -> None:
    """Write a minimal SARIF v2.1.0 report derived from ZAP alerts."""

    alerts: List[Dict[str, Any]] = result.get("alerts", [])
    runs_tool = {
        "driver": {
            "name": "OWASP ZAP",
            "informationUri": "https://www.zaproxy.org/",
            "rules": [],
        }
    }

    rules_index: Dict[str, int] = {}
    rules_list: List[Dict[str, Any]] = []
    sarif_results: List[Dict[str, Any]] = []

    for alert in alerts:
        plugin_id = str(alert.get("pluginId", "") or "ZAP")
        alert_name = str(alert.get("alert", "") or "ZAP Alert")
        risk = str(alert.get("risk", "Informational") or "Informational")
        url = str(alert.get("url", "") or "")

        if plugin_id not in rules_index:
            rules_index[plugin_id] = len(rules_list)
            rules_list.append(
                {
                    "id": plugin_id,
                    "name": alert_name,
                    "shortDescription": {"text": alert_name},
                    "helpUri": "https://www.zaproxy.org/docs/alerts/",
                }
            )

        level = "note"
        if risk.lower() == "high":
            level = "error"
        elif risk.lower() == "medium":
            level = "warning"

        sarif_results.append(
            {
                "ruleId": plugin_id,
                "level": level,
                "message": {"text": alert_name},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": url},
                        }
                    }
                ],
            }
        )

    runs_tool["driver"]["rules"] = rules_list
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": runs_tool,
                "results": sarif_results,
            }
        ],
    }

    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(json.dumps(sarif, indent=2))
    print(f"[+] SARIF report written to {sarif_path}")


if __name__ == "__main__":
    main()


