"""
Advanced OWASP ZAP DAST helper for the CA2 Django project.


What this script does:
- Optionally starts a ZAP daemon in Docker for you (if requested).
- Checks that the ZAP API is reachable before scanning.
- Opens the target URL in ZAP.
- Runs a spider to discover as many URLs as possible.
- Runs an active scan against the discovered URLs.
- Prints a basic summary and can optionally write a JSON report of alerts.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from zapv2 import ZAPv2


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
        _ = zap.core.version()
        return True
    except Exception:
        return False


def start_zap_docker(image: str, port: int, container_name: str) -> None:
    """Attempt to start a ZAP daemon in Docker for automation."""

    print(f"[+] Attempting to start ZAP Docker container '{container_name}' on port {port}...")
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-p",
            f"{port}:{port}",
            image,
            "zap.sh",
            "-daemon",
            "-port",
            str(port),
            "-config",
            "api.disablekey=true",
        ],
        check=False,
    )


def stop_zap_docker(container_name: str) -> None:
    """Best-effort helper to stop and remove the ZAP Docker container."""

    print(f"[+] Stopping ZAP Docker container '{container_name}'...")
    subprocess.run(["docker", "rm", "-f", container_name], check=False)


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
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    poll_delay: float = 2.0,
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

    # Optional form-based authentication.
    user_id: Optional[str] = None
    if login_url and login_username and login_password:
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

        # Create a user within this context.
        user_id = zap.users.new_user(context_id, "ca2-user")
        zap.users.set_credentials(
            context_id,
            user_id,
            f"username={login_username}&password={login_password}",
        )
        zap.users.set_user_enabled(context_id, user_id, "true")
        zap.forcedUser.set_forced_user(context_id, user_id)
        zap.forcedUser.set_forced_user_mode_enabled("true")
        print(f"[+] Authentication configured for user id {user_id}.")

    print(f"[+] Accessing target: {target}")
    zap.urlopen(target)

    print("[+] Starting spider...")
    if user_id is not None:
        scan_id = zap.spider.scan_as_user(context_id, user_id, target)
    else:
        scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"  - Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(poll_delay)

    print("[+] Starting active scan...")
    if user_id is not None:
        active_id = zap.ascan.scan_as_user(context_id, user_id, target)
    else:
        active_id = zap.ascan.scan(target)
    while int(zap.ascan.status(active_id)) < 100:
        print(f"  - Active scan progress: {zap.ascan.status(active_id)}%")
        time.sleep(poll_delay)

    alerts = zap.core.alerts()
    print(f"[+] Scan complete. Total alerts: {len(alerts)}")

    # Basic severity summary.
    severities: Dict[str, int] = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in alerts:
        risk = alert.get("risk", "Informational")
        if risk in severities:
            severities[risk] += 1
        else:
            severities["Informational"] += 1

    result: Dict[str, Any] = {
        "target": target,
        "context_id": context_id,
        "user_id": user_id,
        "alerts": alerts,
        "severity_summary": severities,
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
                "## Severity counts",
            ]
            for sev, count in severities.items():
                md_lines.append(f"- **{sev}**: {count}")
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
        "--auto-docker",
        action="store_true",
        help="If set, attempt to start a ZAP Docker container automatically when needed.",
    )
    parser.add_argument(
        "--docker-image",
        default="owasp/zap2docker-stable",
        help="Docker image to use when --auto-docker is enabled.",
    )
    parser.add_argument(
        "--docker-container",
        default="zap-ca2",
        help="Docker container name to use when --auto-docker is enabled.",
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
        "--auto",
        action="store_true",
        help=(
            "Run a full automatic scan with sensible defaults suitable for "
            "CA2 demonstrations (auto-Docker, reports under logs/zap_reports, "
            "HTML/JSON/MD outputs, and standard excludes for static/admin paths)."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_json = Path(args.output_json) if args.output_json else None
    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    output_base = Path(args.output_prefix) if args.output_prefix else None

    # Auto mode: turn on Docker, set a sensible output prefix under logs/zap_reports
    # and default to multiple formats.
    if args.auto:
        args.auto_docker = True
        if output_base is None:
            # Derive a simple base name from the target host.
            safe_target = args.target.replace("://", "_").replace("/", "_")
            output_base = Path("logs") / "zap_reports" / f"zap_auto_{safe_target}"
        if not formats:
            formats = ["json", "html", "md"]

    # Quick availability check for the target before we start ZAP work.
    if not check_target_available(args.target, insecure=args.insecure):
        return

    # Check if ZAP is already reachable; if not, either offer auto-Docker or
    # ask the user to start it manually.
    if not is_zap_reachable(args.api_key, args.zap_host, args.zap_port):
        print("[!] No running ZAP daemon detected on "
              f"{args.zap_host}:{args.zap_port}.")

        if args.auto_docker:
            start_zap_docker(args.docker_image, args.zap_port, args.docker_container)
            # Give Docker some time to start ZAP and then poll for readiness.
            for _ in range(30):
                time.sleep(2)
                if is_zap_reachable(args.api_key, args.zap_host, args.zap_port):
                    print("[+] ZAP Docker container is up and responding.")
                    break
            else:
                print("[!] ZAP still not responding after starting Docker. "
                      "Please check Docker manually.")
                return
        else:
            answer = input(
                "[?] Would you like this script to start ZAP in Docker for you? [y/N]: "
            ).strip().lower()
            if answer == "y":
                start_zap_docker(args.docker_image, args.zap_port, args.docker_container)
                for _ in range(30):
                    time.sleep(2)
                    if is_zap_reachable(args.api_key, args.zap_host, args.zap_port):
                        print("[+] ZAP Docker container is up and responding.")
                        break
                else:
                    print("[!] ZAP still not responding after starting Docker. "
                          "Please check Docker manually.")
                    return
            else:
                print(
                    "[!] Please start a ZAP daemon manually (for example:\n"
                    "    docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable "
                    "zap.sh -daemon -port 8080\n"
                    "    ) and re-run this script."
                )
                return

    try:
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
            include=args.include,
            exclude=args.exclude,
            poll_delay=args.poll_delay,
        )
    finally:
        # If we started Docker automatically, clean it up.
        if args.auto_docker:
            stop_zap_docker(args.docker_container)

    # Optionally fail the process based on alert severities (CI-style usage).
    if result is not None:
        severities = result.get("severity_summary", {})
        high = int(severities.get("High", 0) or 0)
        medium = int(severities.get("Medium", 0) or 0)

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


if __name__ == "__main__":
    main()


