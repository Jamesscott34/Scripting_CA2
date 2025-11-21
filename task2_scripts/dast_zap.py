"""
Advanced OWASP ZAP DAST helper for the CA2 Django project.

Assumptions:
- You are authorised to test the target application.

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
from typing import Any, Dict, Optional

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


def run_dast(
    target: str,
    api_key: str,
    zap_host: str,
    zap_port: int,
    output_json: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run a spider + active scan against the target and return ZAP alerts."""

    zap = _zap_client(api_key, zap_host, zap_port)

    print(f"[+] Accessing target: {target}")
    zap.urlopen(target)

    print("[+] Starting spider...")
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"  - Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)

    print("[+] Starting active scan...")
    active_id = zap.ascan.scan(target)
    while int(zap.ascan.status(active_id)) < 100:
        print(f"  - Active scan progress: {zap.ascan.status(active_id)}%")
        time.sleep(2)

    alerts = zap.core.alerts()
    print(f"[+] Scan complete. Total alerts: {len(alerts)}")

    result: Dict[str, Any] = {"target": target, "alerts": alerts}

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(json.dumps(result, indent=2))
        print(f"[+] JSON DAST report written to {output_json}")

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an OWASP ZAP DAST scan against the CA2 Django app or another target."
    )
    parser.add_argument(
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_json = Path(args.output_json) if args.output_json else None

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
        run_dast(args.target, args.api_key, args.zap_host, args.zap_port, output_json)
    finally:
        # If we started Docker automatically, clean it up.
        if args.auto_docker:
            stop_zap_docker(args.docker_container)


if __name__ == "__main__":
    main()


