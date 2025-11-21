"""
Fuzz testing helper script for the CA2 website.

This script is intentionally simple but demonstrates several important ideas:

- Sending unexpected input (including punctuation and long strings) to HTTP
  endpoints to see how they behave under stress.
- Supporting multiple HTTP methods (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS).
- Fuzzing both **query parameters** and **request bodies** (JSON or form),
  including optional multipart file uploads.
- Using structured **payload categories** (SQLi, XSS, path traversal, Unicode,
  Django template injections) loaded from a JSON library file.
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

# Path to JSON file defining structured payload categories.
PAYLOAD_LIBRARY_PATH = Path(__file__).with_name("payloads.json")


def load_payload_library() -> Dict[str, List[str]]:
    """
    Load structured payload categories from a JSON file.

    The JSON file maps category names (e.g. "sql", "xss", "django") to lists of
    payload strings. This makes it easy to extend the fuzzer without changing
    any Python code.
    """
    if not PAYLOAD_LIBRARY_PATH.exists():
        return {}

    try:
        with PAYLOAD_LIBRARY_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        # Fail closed: if the file is unreadable or invalid, just return an
        # empty mapping and fall back to purely random payload generation.
        return {}

    # Normalise all values to lists of strings.
    library: Dict[str, List[str]] = {}
    for name, values in data.items():
        if isinstance(values, list):
            library[name] = [str(v) for v in values]
    return library


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


def build_files(payload: str, enable_files: bool) -> Optional[Dict[str, Tuple[str, bytes, str]]]:
    """
    Optionally build a multipart file upload payload.

    The contents of the generated "file" are not intended to be realistic
    documents; instead we focus on sending arbitrarily-sized blobs which can
    trigger validation and size-handling paths in the target application.
    """
    if not enable_files:
        return None

    # Use the payload as the basis of the file content, expanding it if
    # necessary to exercise larger upload paths.
    content = payload
    if len(content) < 1024:
        # Repeat the payload until we reach at least ~1KB.
        repeat = max(1, 1024 // max(1, len(content)))
        content = (content or "X") * repeat

    filename = "fuzz_upload.txt"
    mime_type = "text/plain"
    return {"file": (filename, content.encode("utf-8", errors="ignore"), mime_type)}


def mutate_payload(payload: str) -> str:
    """
    Apply a simple mutation to a payload string.

    The goal is not to be exhaustive like AFL, but to introduce small,
    repeatable distortions that may trigger edge cases in parsers and
    validation logic.
    """
    if not payload:
        return payload

    choice = random.choice(
        ["invert_case", "duplicate", "delete", "insert_special", "reverse"]
    )

    if choice == "invert_case":
        return "".join(
            c.lower() if c.isupper() else c.upper() if c.islower() else c
            for c in payload
        )

    if choice == "duplicate":
        idx = random.randrange(len(payload))
        return payload[:idx] + payload[idx] * 2 + payload[idx + 1 :]

    if choice == "delete" and len(payload) > 1:
        idx = random.randrange(len(payload))
        return payload[:idx] + payload[idx + 1 :]

    if choice == "insert_special":
        specials = "!@#$%^&*()[]{}<>?/\\|"
        idx = random.randrange(len(payload) + 1)
        ch = random.choice(specials)
        return payload[:idx] + ch + payload[idx:]

    # "reverse" or fallback
    return payload[::-1]


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
    payload_category: Optional[str] = None,
    mutate: bool = False,
    fuzz_files: bool = False,
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

    payload_library: Dict[str, List[str]] = {}
    if payload_category:
        payload_library = load_payload_library()
        if payload_category not in payload_library:
            print(
                f"[!] Payload category '{payload_category}' was not found in "
                f"{PAYLOAD_LIBRARY_PATH}. Falling back to random strings."
            )
            payload_category = None

    for i in range(1, iterations + 1):
        # Choose a base payload, optionally from a structured category.
        if payload_category and payload_library:
            base = random.choice(payload_library[payload_category])
            if payload_mode == "buffer_overflow":
                # Amplify the category payload into a very large string.
                repeat = max(1, 10_000 // max(1, len(base)))
                base = base * repeat
        else:
            # In "buffer_overflow" mode we deliberately generate a very large
            # payload (e.g. 50k characters) to test how the endpoint handles
            # large inputs. This is safe at the Python level but can reveal
            # size-related issues in downstream components.
            if payload_mode == "buffer_overflow":
                base = random_string(10_000, 50_000)
            else:
                base = random_string(0, 80)

        if mutate:
            base = mutate_payload(base)

        params = {"q": base}

        json_body, form_body = build_bodies(
            payload=base,
            body_type=body_type,
        )

        files = build_files(base, enable_files=fuzz_files)

        # When sending multipart/form-data with files we typically pair it with
        # simple form fields rather than JSON bodies.
        effective_json = None if files else json_body

        last_exc: Optional[Exception] = None
        for attempt in range(1, retries + 1):
            try:
                resp = requests.request(
                    method,
                    url,
                    params=params,
                    json=effective_json,
                    data=form_body,
                    files=files,
                    timeout=timeout,
                    verify=verify,
                )
                status_codes.append(resp.status_code)
                samples.append(
                    {
                        "iteration": i,
                        "params": params,
                        "json": effective_json,
                        "data": form_body,
                        "has_file": bool(files),
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
                    "json": effective_json,
                    "data": form_body,
                    "has_file": bool(files),
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
    category_suffix = "" if not payload_category else f"_{payload_category}"

    # Always ensure a logs directory for human-readable logs.
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"fuzz_{safe_host}_{date_str}{mode_suffix}{category_suffix}.log"

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

    json_path = output_dir / f"fuzz_{safe_host}_{date_str}{mode_suffix}{category_suffix}.json"

    data = {
        "mode": os.getenv("SECURE_MODE", "unknown"),
        "base_url": base_url,
        "path": path,
      "iterations": iterations,
      "payload_mode": payload_mode,
      "payload_category": payload_category,
      "mutate_payloads": mutate,
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
        "--payload-category",
        default=None,
        choices=["sql", "xss", "path", "unicode", "django"],
        help=(
            "Optional payload category to use instead of purely random fuzz "
            "strings. Categories are loaded from payloads.json."
        ),
    )
    parser.add_argument(
        "--all-categories",
        action="store_true",
        help=(
            "Run fuzzing once per known payload category. Each category will "
            "produce its own log and JSON report."
        ),
    )
    parser.add_argument(
        "--mutate-payloads",
        action="store_true",
        help=(
            "Apply a simple mutation engine to each payload (invert case, "
            "insert special characters, duplicate/delete characters, etc.)."
        ),
    )
    parser.add_argument(
        "--fuzz-files",
        action="store_true",
        help=(
            "Enable multipart file upload fuzzing alongside query/body fuzzing. "
            "This is useful for testing upload endpoints such as profile image "
            "or document submission views."
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
    # Decide which payload categories to run.
    if args.all_categories:
        library = load_payload_library()
        categories: List[Optional[str]] = sorted(library.keys())
        if not categories:
            print(
                "[!] No payload categories found in payloads.json; "
                "falling back to purely random payloads."
            )
            categories = [None]
    else:
        categories = [args.payload_category]

    for category in categories:
        if category:
            print(f"[*] Using payload category: {category}")

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
                payload_category=category,
                mutate=args.mutate_payloads,
                fuzz_files=args.fuzz_files,
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
                payload_category=category,
                mutate=args.mutate_payloads,
                fuzz_files=args.fuzz_files,
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
                payload_category=category,
                mutate=args.mutate_payloads,
                fuzz_files=args.fuzz_files,
            )


if __name__ == "__main__":
    main()


