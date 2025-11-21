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
import re
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

# Path to JSON file defining structured payload categories.
PAYLOAD_LIBRARY_PATH = Path(__file__).with_name("payloads.json")

# Default endpoints to fuzz when running in full automatic mode. These are
# chosen to work well with the CA2 banking application but are also sensible
# guesses for many generic web applications.
AUTO_PATHS = [
    "/",                 # landing page / dashboard
    "/accounts/login/",  # Django auth login
    "/login/",           # common custom login path
    "/profile/",         # user profile
    "/dashboard/",       # overview/dashboard
    "/search/",          # search endpoint
]


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


def build_authenticated_session(
    base_url: str,
    login_url: Optional[str],
    username: Optional[str],
    password: Optional[str],
    insecure: bool,
    timeout: float,
) -> Optional[requests.Session]:
    """
    Optionally perform a simple login flow and return an authenticated session.

    This helper is intentionally conservative and tuned for Django-style login
    views:

    - It performs a GET to fetch the login page and CSRF token.
    - It then POSTs the username/password (and CSRF token if found).
    - Any cookies set during this process are reused for subsequent fuzzing.

    If any required parameter is missing or the login flow fails, the function
    returns ``None`` and fuzzing falls back to unauthenticated requests.
    """
    if not (login_url and username and password):
        return None

    session = requests.Session()
    verify = not insecure
    full_login_url = base_url.rstrip("/") + "/" + login_url.lstrip("/")

    try:
        # Fetch login page to obtain CSRF cookie and token.
        resp = session.get(full_login_url, timeout=timeout, verify=verify)
    except requests.RequestException as exc:
        print(f"[!] Failed to fetch login page {full_login_url}: {exc}")
        return None

    csrf_token = session.cookies.get("csrftoken")
    if not csrf_token:
        # Try to extract from HTML as a fallback.
        match = re.search(
            r"name=['\"]csrfmiddlewaretoken['\"][^>]*value=['\"]([^'\"]+)['\"]",
            resp.text,
            flags=re.IGNORECASE,
        )
        if match:
            csrf_token = match.group(1)

    data: Dict[str, str] = {
        "username": username,
        "password": password,
    }
    if csrf_token:
        data["csrfmiddlewaretoken"] = csrf_token

    try:
        post_resp = session.post(
            full_login_url,
            data=data,
            timeout=timeout,
            verify=verify,
        )
        if post_resp.status_code >= 400:
            print(
                f"[!] Login POST to {full_login_url} returned status "
                f"{post_resp.status_code}; continuing without auth."
            )
            return None
    except requests.RequestException as exc:
        print(f"[!] Failed to perform login POST to {full_login_url}: {exc}")
        return None

    print(f"[+] Authenticated session established via {full_login_url}")
    return session


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
    session: Optional[requests.Session] = None,
    aggregate: Optional[List[Dict[str, object]]] = None,
    write_files: bool = True,
) -> None:
    """
    Send fuzzed HTTP requests to the given endpoint and print basic stats.

    This helper supports:
    - Multiple HTTP methods (GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD).
    - Query-string, JSON body, and form body fuzzing.
    - Optional multipart file upload fuzzing.
    - Optional structured payload categories and mutation.
    - Optional reuse of an authenticated ``requests.Session``.
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
                client = session or requests
                resp = client.request(
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
    # Incorporate the endpoint path into filenames so that different endpoints
    # fuzzed on the same host do not overwrite one another.
    safe_path = path.strip("/") or "root"
    safe_path = safe_path.replace("/", "_").replace(" ", "_")
    date_str = datetime.now().strftime("%d%m%y")
    mode_suffix = "" if payload_mode == "random" else f"_{payload_mode}"
    category_suffix = "" if not payload_category else f"_{payload_category}"

    mode_value = os.getenv("SECURE_MODE")
    if mode_value is None:
        # When fuzzing external targets there is no secure/insecure mode; use a
        # descriptive fallback instead of "unknown".
        mode_value = "external"

    data = {
        "mode": mode_value,
        "base_url": base_url,
        "path": path,
        "iterations": iterations,
        "payload_mode": payload_mode,
        "payload_category": payload_category,
        "mutate_payloads": mutate,
        "samples": samples,
    }
    # Optionally add this run to an aggregate structure for combined reporting
    # (single JSON / log / Excel file).
    if aggregate is not None:
        aggregate.append(data)

    if write_files:
        # Always ensure a logs directory for human-readable logs.
        logs_dir = Path("logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"fuzz_{safe_host}_{safe_path}_{date_str}{mode_suffix}{category_suffix}.log"

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

        json_path = output_dir / f"fuzz_{safe_host}_{safe_path}_{date_str}{mode_suffix}{category_suffix}.json"

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
        "-t",
        "--target",
        default=None,
        help=(
            "Optional convenience alias for --base-url. If provided, this "
            "value overrides --base-url and is used as the fuzz target "
            "(e.g. http://127.0.0.1:8001 or https://example.com)."
        ),
    )
    parser.add_argument(
        "--path",
        default="/search/",
        help="Endpoint path to fuzz (default: /search/).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        #change this to whatever you want auto to run at 
        default=20,
        help="Number of fuzzing iterations per run (default: 20).",
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
        "--auto",
        action="store_true",
        help=(
            "Full automatic mode: enables mode=auto, all payload categories, "
            "payload mutation, and file upload fuzzing for the chosen path."
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
    parser.add_argument(
        "--login-url",
        default=None,
        help=(
            "Optional path to a login view (relative to base URL), or the "
            "special value 'auto'. When set together with "
            "--login-username and --login-password, the fuzzer will "
            "establish an authenticated session before sending requests. "
            "When set to 'auto', common Django-style login paths such as "
            "/accounts/login/ and /login/ will be tried in order."
        ),
    )
    parser.add_argument(
        "--login-username",
        default=None,
        help="Username to use for the optional login flow.",
    )
    parser.add_argument(
        "--login-password",
        default=None,
        help="Password to use for the optional login flow.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # --target is a user-friendly alias for --base-url.
    if args.target:
        args.base_url = args.target

    # Full automatic mode turns on a rich combination of features suitable for
    # demonstrations: both payload modes, all categories, mutation, and file
    # uploads.
    if args.auto:
        args.mode = "auto"
        args.all_categories = True
        args.mutate_payloads = True
        args.fuzz_files = True
        print(
            "[*] Full auto mode enabled: mode=auto, all payload categories, "
            "payload mutation, and file upload fuzzing."
        )

    output_json = Path(args.output_json) if args.output_json else None
    # Optionally establish an authenticated session. When --login-url=auto is
    # used we try a small set of common login paths in order until one works.
    session: Optional[requests.Session] = None
    login_paths: List[str] = []
    if args.login_url == "auto":
        login_paths = ["/accounts/login/", "/login/"]
    elif args.login_url:
        login_paths = [args.login_url]

    if args.login_username and args.login_password and login_paths:
        for login_path in login_paths:
            candidate = build_authenticated_session(
                base_url=args.base_url,
                login_url=login_path,
                username=args.login_username,
                password=args.login_password,
                insecure=args.insecure,
                timeout=args.timeout,
            )
            if candidate is not None:
                session = candidate
                break
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

    # Decide which endpoint paths to run.
    if args.auto:
        paths = AUTO_PATHS
    else:
        paths = [args.path]

    # In full auto mode we also build a combined in-memory representation of
    # all fuzz runs, which can later be written to a single JSON/log/Excel
    # report in addition to the per-run artefacts.
    aggregate_runs: Optional[List[Dict[str, object]]] = [] if args.auto else None

    for path in paths:
        print(f"[*] Fuzzing path: {path}")
        for category in categories:
            if category:
                print(f"[*] Using payload category: {category}")

            # In mode=auto we run *both* random and buffer_overflow fuzzing.
            # When args.auto is set we only write aggregate outputs, not per-run
            # JSON/log files.
            write_files = not args.auto

            if args.mode == "auto":
                output_dir = output_json
                print("[*] Auto mode: running random fuzzing first...")
                fuzz_endpoint(
                    args.base_url,
                    path,
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
                    session=session,
                    aggregate=aggregate_runs,
                    write_files=write_files,
                )
                print("[*] Auto mode: running buffer_overflow fuzzing...")
                fuzz_endpoint(
                    args.base_url,
                    path,
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
                    session=session,
                    aggregate=aggregate_runs,
                    write_files=write_files,
                )
            else:
                fuzz_endpoint(
                    args.base_url,
                    path,
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
                    session=session,
                    aggregate=aggregate_runs,
                    write_files=write_files,
                )

    # If we have collected aggregate data (full auto mode), emit combined JSON,
    # log and an Excel workbook with one sheet per run.
    if aggregate_runs:
        parsed = urlparse(args.base_url)
        host = parsed.netloc or parsed.path or "unknown"
        safe_host = host.replace(":", "_").replace(".", "_")
        date_str = datetime.now().strftime("%d%m%y")

        aggregate_dir = Path("logs") / "json_logs"
        aggregate_dir.mkdir(parents=True, exist_ok=True)
        aggregate_json_path = aggregate_dir / f"fuzz_all_{safe_host}_{date_str}.json"

        aggregate_payload = {
            "base_url": args.base_url,
            "generated_at": datetime.now().isoformat(),
            "runs": aggregate_runs,
        }
        aggregate_json_path.write_text(json.dumps(aggregate_payload, indent=2))
        print(f"[+] Aggregate JSON report written to {aggregate_json_path}")

        # Aggregate text log with a short summary per run.
        log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        aggregate_log_path = log_dir / f"fuzz_all_{safe_host}_{date_str}.log"

        log_lines: List[str] = [
            f"Aggregate fuzzing report for {args.base_url}",
            f"Generated at: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
            "",
        ]
        for run in aggregate_runs:
            samples = run.get("samples", [])
            status_list = [
                s.get("status_code")
                for s in samples
                if s.get("status_code") is not None
            ]
            status_counts: Dict[int, int] = {}
            for code in status_list:
                status_counts[code] = status_counts.get(code, 0) + 1

            log_lines.append(
                f"Path: {run.get('path')} | mode: {run.get('payload_mode')} | "
                f"category: {run.get('payload_category')}"
            )
            log_lines.append(f"  Iterations: {run.get('iterations')}")
            log_lines.append("  Status codes:")
            for code in sorted(status_counts.keys()):
                log_lines.append(f"    {code}: {status_counts[code]}")
            log_lines.append("")

        aggregate_log_path.write_text("\n".join(log_lines))
        print(f"[+] Aggregate text log written to {aggregate_log_path}")

        # Optional Excel export: requires openpyxl; if unavailable we skip
        # gracefully.
        try:
            from openpyxl import Workbook  # type: ignore

            excel_dir = Path("logs") / "excel"
            excel_dir.mkdir(parents=True, exist_ok=True)
            excel_path = excel_dir / f"fuzz_all_{safe_host}_{date_str}.xlsx"

            wb = Workbook()
            first_sheet = True
            # Use the host (URL/IP) as the base worksheet title, truncated to
            # Excel's 31-character limit. This avoids long, unreadable titles
            # and the associated openpyxl warnings.
            base_title = safe_host[:31] or "target"

            for _run_idx, run in enumerate(aggregate_runs, start=1):
                title = base_title

                if first_sheet:
                    ws = wb.active
                    ws.title = title
                    first_sheet = False
                else:
                    ws = wb.create_sheet(title=title)

                ws.append(
                    [
                        "iteration",
                        "path",
                        "payload_mode",
                        "payload_category",
                        "has_file",
                        "status_code",
                    ]
                )
                for s in run.get("samples", []):
                    ws.append(
                        [
                            s.get("iteration"),
                            run.get("path"),
                            run.get("payload_mode"),
                            run.get("payload_category"),
                            s.get("has_file", False),
                            s.get("status_code"),
                        ]
                    )

            wb.save(excel_path)
            print(f"[+] Aggregate Excel report written to {excel_path}")
        except ImportError:
            print(
                "[!] openpyxl is not installed; skipping Excel export. "
                "Install it with 'pip install openpyxl' to enable Excel output."
            )


if __name__ == "__main__":
    main()


