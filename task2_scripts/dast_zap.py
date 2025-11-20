"""
Simple OWASP ZAP DAST helper for the CA2 Django project.

This assumes a ZAP daemon is already running (e.g. Docker) and exposes its API.
It performs a spider followed by an active scan against a target URL and prints
basic findings.
"""

import argparse
from typing import Any, Dict

from zapv2 import ZAPv2


def run_dast(target: str, api_key: str, zap_host: str, zap_port: int) -> Dict[str, Any]:
    zap = ZAPv2(apikey=api_key, proxies={"http": f"http://{zap_host}:{zap_port}", "https": f"http://{zap_host}:{zap_port}"})

    print(f"[+] Accessing target: {target}")
    zap.urlopen(target)

    print("[+] Starting spider...")
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"  - Spider progress: {zap.spider.status(scan_id)}%")

    print("[+] Starting active scan...")
    active_id = zap.ascan.scan(target)
    while int(zap.ascan.status(active_id)) < 100:
        print(f"  - Active scan progress: {zap.ascan.status(active_id)}%")

    alerts = zap.core.alerts()
    print(f"[+] Scan complete. Total alerts: {len(alerts)}")
    return {"alerts": alerts}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a basic OWASP ZAP DAST scan against the CA2 Django app."
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_dast(args.target, args.api_key, args.zap_host, args.zap_port)


if __name__ == "__main__":
    main()


