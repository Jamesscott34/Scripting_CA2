"""
Fuzz testing helper script for the CA2 Django banking application.

This script is intentionally simple but demonstrates several important ideas:

- Sending unexpected input (including punctuation and long strings) to HTTP
  endpoints to see how they behave under stress.
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
from pathlib import Path
from typing import List, Optional

import requests


def random_string(min_len: int = 1, max_len: int = 50) -> str:
    """Generate a random ASCII string in the given length range."""
    length = random.randint(min_len, max_len)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(alphabet) for _ in range(length))


def fuzz_endpoint(
    base_url: str,
    path: str,
    iterations: int,
    output_json: Optional[Path] = None,
    payload_mode: str = "random",
) -> None:
    """
    Send randomised GET requests to the given endpoint and print basic stats.

    This is deliberately simple and safe; it is *not* a full fuzzing framework
    but demonstrates the idea of unexpected input testing.
    """
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    print(f"[+] Fuzzing endpoint: {url} (iterations={iterations})")
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
        try:
            resp = requests.get(url, params=params, timeout=5)
            status_codes.append(resp.status_code)
            samples.append(
                {
                    "iteration": i,
                    "params": params,
                    "status_code": resp.status_code,
                }
            )
            if i % 10 == 0:
                print(f"  - Iteration {i}: status {resp.status_code}")
        except requests.RequestException as exc:
            print(f"  ! Request error at iteration {i}: {exc}")

    print("[+] Fuzzing complete. Status code counts:")
    for code in sorted(set(status_codes)):
        print(f"    {code}: {status_codes.count(code)}")

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "mode": os.getenv("SECURE_MODE", "unknown"),
            "base_url": base_url,
            "path": path,
            "iterations": iterations,
             "payload_mode": payload_mode,
            "samples": samples,
        }
        output_json.write_text(json.dumps(data, indent=2))
        print(f"[+] JSON fuzz report written to {output_json}")


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
        "--mode",
        choices=["random", "buffer_overflow"],
        default="random",
        help=(
            "Payload mode: 'random' sends varied short/medium inputs; "
            "'buffer_overflow' sends very large payloads to test robustness."
        ),
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional path to write a JSON report of fuzzed queries and status codes.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_json = Path(args.output_json) if args.output_json else None
    fuzz_endpoint(
        args.base_url,
        args.path,
        args.iterations,
        output_json=output_json,
        payload_mode=args.mode,
    )


if __name__ == "__main__":
    main()


