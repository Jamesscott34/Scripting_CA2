"""
Fuzz testing helper script for the CA2 website.

This script is intentionally simple but demonstrates several important ideas:

- Sending unexpected input (including punctuation and long strings) to HTTP
  endpoints to see how they behave under stress.
- Supporting multiple HTTP methods (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS).
- Fuzzing both **query parameters** and **request bodies** (JSON or form).
- Recording every request/response pair in a JSON file for later analysis or
  inclusion in a security report.
- A "buffer_overflow" style mode that generates *very* long payloads to test
  how the application handles large request sizes.

It is not a full fuzzing framework, but it is production-ready enough to be
used as a teaching tool and a starting point for more advanced testing.
"""

import argparse
import json
import os
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


def random_string(min_len: int = 1, max_len: int = 50) -> str:
    """Generate a random ASCII string in the given length range."""
    length = random.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(alphabet) for _ in range(length))


def build_bodies(payload: str, body_type: str) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, str]]]:
    """
    Build JSON or form bodies for fuzzing.

    For now we use a simple banking-style schema that works well against the
    CA2 project and many generic login/transfer endpoints:

    {
        "username": "<fuzz>",
        "password": "<fuzz>",
        "transfer_amount": "<fuzz>"
    }
    """

    if body_type == "json":
        return {
            "username": payload,
            "password": payload,
            "transfer_amount": payload,
        }, None

    if body_type == "form":
        return None, {
            "username": payload,
            "password": payload,
            "transfer_amount": payload,
        }

    return None, None


def fuzz_endpoint(
    base_url: str,
    path: str,
    iterations: int,
    output_json: Optional[Path] = None,
    payload_mode: str = "random",
    method: str = "GET",
    body_type: str = "none",
    insecure: bool = False,
    timeout: float = 5.0,
    retries: int = 1,
) -> None:
    """
    Send randomised GET requests to the given endpoint and print basic stats.

    This is deliberately simple and safe; it is *not* a full fuzzing framework
    but demonstrates the idea of unexpected input testing.
    """
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    method = method.upper()
    verify = not insecure

    print(f"[+] Fuzzing endpoint: {method} {url} (iterations={iterations})")
    status_codes: List[int] = []
    samples = []

    for i in range(1, iterations + 1):
        # In "buffer_overflow" mode we deliberately generate a very large
        # payload (e.g. 50k characters) to test how the endpoint handles
        # large inputs. This is safe at the Python level but can reveal
        # size-related issues in downstream components.
        if payload_mode == "buffer_overflow":
            params = {"q": random_string(10_000, 50_000)}
        else:
            params = {"q": random_string(0, 80)}

        json_body, form_body = build_bodies(
            payload=params["q"],
            body_type=body_type,
        )

        last_exc: Optional[Exception] = None
        for attempt in range(1, retries + 1):
            try:
                resp = requests.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    data=form_body,
                    timeout=timeout,
                    verify=verify,
                )
                status_codes.append(resp.status_code)
                samples.append(
                    {
                        "iteration": i,
                        "params": params,
                        "json": json_body,
                        "data": form_body,
                        "status_code": resp.status_code,
                    }
                )
                if i % 10 == 0:
                    print(f"  - Iteration {i}: status {resp.status_code}")
                break
            except requests.RequestException as exc:
                last_exc = exc
                print(f"  ! Request error at iteration {i} (attempt {attempt}): {exc}")
                if attempt < retries:
                    continue

        if last_exc and retries > 1:
            # Even after retries we could not get a response; record a pseudo-entry.
            samples.append(
                {
                    "iteration": i,
                    "params": params,
                    "json": json_body,
                    "data": form_body,
                    "status_code": None,
                    "error": str(last_exc),
                }
            )

    print("[+] Fuzzing complete. Status code counts:")
    for code in sorted(set(status_codes)):
        print(f"    {code}: {status_codes.count(code)}")

    # Determine output directory and filenames.
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path or "unknown"
    safe_host = host.replace(":", "_").replace(".", "_")
    date_str = datetime.now().strftime("%d%m%y")
    mode_suffix = "" if payload_mode == "random" else f"_{payload_mode}"

    # Always ensure a logs directory for human-readable logs.
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"fuzz_{safe_host}_{date_str}{mode_suffix}.log"

    # If no JSON directory was provided, default to logs/json_logs.
    if output_json is None:
        output_dir = Path("logs") / "json_logs"
    else:
        # Treat output_json as a directory hint; if it includes a filename
        # (e.g. ends with .json), we use its parent as the directory instead.
        if output_json.suffix and not output_json.is_dir():
            output_dir = output_json.parent
        else:
            output_dir = output_json
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / f"fuzz_{safe_host}_{date_str}{mode_suffix}.json"

    data = {
        "mode": os.getenv("SECURE_MODE", "unknown"),
        "base_url": base_url,
        "path": path,
        "iterations": iterations,
        "payload_mode": payload_mode,
        "samples": samples,
    }
    json_path.write_text(json.dumps(data, indent=2))
    print(f"[+] JSON fuzz report written to {json_path}")

    # Also write a short text log summarising the run.
    summary_lines = [
        f"Timestamp: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        f"Mode: {data['mode']}",
        f"Base URL: {base_url}",
        f"Path: {path}",
        f"Iterations: {iterations}",
        f"Payload mode: {payload_mode}",
        "",
        "Status code counts:",
        *(f"  {code}: {status_codes.count(code)}" for code in sorted(set(status_codes))),
        "",
        f"JSON report: {json_path}",
    ]
    log_path.write_text("\n".join(summary_lines))
    print(f"[+] Text fuzz log written to {log_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple HTTP fuzz tester for the CA2 Django application."
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL of the running Django app (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--path",
        default="/search/",
        help="Endpoint path to fuzz (default: /search/).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Number of fuzzing iterations (default: 100).",
    )
    parser.add_argument(
        "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        help="HTTP method to use when sending requests (default: GET).",
    )
    parser.add_argument(
        "--body-type",
        default="none",
        choices=["none", "json", "form"],
        help=(
            "Whether to also fuzz request bodies: 'json' sends a JSON object "
            "with fuzzed fields; 'form' sends application/x-www-form-urlencoded "
            "data; 'none' only fuzzes query parameters."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["random", "buffer_overflow", "auto"],
        default="random",
        help=(
            "Payload mode: 'random' sends varied short/medium inputs; "
            "'buffer_overflow' sends very large payloads to test robustness; "
            "'auto' runs both modes one after the other."
        ),
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to write a JSON report of fuzzed queries and status codes.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (like curl -k).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Request timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Number of times to retry a request on network errors (default: 1).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_json = Path(args.output_json) if args.output_json else None
    # In auto mode we run *both* random and buffer_overflow fuzzing.
    if args.mode == "auto":
        output_dir = output_json
        print("[*] Auto mode: running random fuzzing first...")
        fuzz_endpoint(
            args.base_url,
            args.path,
            args.iterations,
            output_json=output_dir,
            payload_mode="random",
            method=args.method,
            body_type=args.body_type,
            insecure=args.insecure,
            timeout=args.timeout,
            retries=args.retries,
        )
        print("[*] Auto mode: running buffer_overflow fuzzing...")
        fuzz_endpoint(
            args.base_url,
            args.path,
            args.iterations,
            output_json=output_dir,
            payload_mode="buffer_overflow",
            method=args.method,
            body_type=args.body_type,
            insecure=args.insecure,
            timeout=args.timeout,
            retries=args.retries,
        )
    else:
        fuzz_endpoint(
            args.base_url,
            args.path,
            args.iterations,
            output_json=output_json,
            payload_mode=args.mode,
            method=args.method,
            body_type=args.body_type,
            insecure=args.insecure,
            timeout=args.timeout,
            retries=args.retries,
        )


if __name__ == "__main__":
    main()


