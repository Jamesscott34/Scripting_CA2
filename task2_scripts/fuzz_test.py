"""
Advanced HTTP fuzzing engine for the CA2 secure scripting project.

This script is a focused but capable fuzzer It demonstrates a number of real-world fuzzing concepts:

- Sending unexpected input (including punctuation and very long strings) to
  HTTP endpoints to see how they behave under stress.
- Supporting multiple HTTP methods (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS).
- Fuzzing both **query parameters** and **request bodies** (JSON or form),
  including optional multipart file uploads to exercise upload endpoints.
- Using structured **payload categories** (SQLi, XSS, path traversal, Unicode,
  Django template injections) from a built-in library, with an optional
  mutation engine to distort payloads (invert case, insert special chars,
  delete/duplicate characters, reverse strings, etc.).
- Recording every request/response pair in JSON for later analysis and writing
  per-run and aggregate text logs and Excel reports.
- A "buffer_overflow" style mode that generates very large payloads to test
  how the application handles large request sizes and potential DoS conditions.
- Optional **authenticated fuzzing** using a Django-style login flow with CSRF
  token handling and session cookie reuse.
- Header and cookie fuzzing via external JSON files and `<fuzz>` placeholders.
- **Replay** and **replay-mutate** modes to resend payloads from previous
  reports to confirm or explore interesting behaviour.
- Threaded fuzzing (`--threads`) to run multiple endpoint/category jobs in
  parallel.
- Built-in anomaly detection (5xx errors, error signatures, slow/large
  responses, reflection, redirect loops, rate-limiting) with approximate
  OWASP Top 10 mapping and simple input coverage summaries printed at the end
  of each run.

"""

import argparse
import json
import os
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

SCRIPT_ROOT = Path(__file__).resolve().parent
LOGS_ROOT = SCRIPT_ROOT / "logs"

# Default endpoints to fuzz when running in full automatic mode. These are
# common REST / web
# patterns you see in typical applications.
AUTO_PATHS = [
    "/",                      # landing page / dashboard
    "/index",                 # alternate landing page
    "/home",                  # alternate landing page

    # Authentication / account management.
    "/accounts/login/",       # Django auth login
    "/login/",                # common custom login path (Django / generic)
    "/login",                 # Flask insecure app login
    "/logout",                # logout endpoint
    "/register",              # Flask insecure registration
    "/register/",             # alternate registration path
    "/signup",                # common registration alias
    "/signup/",               # common registration alias
    "/reset-password",        # password reset
    "/reset-password/",       # password reset
    "/forgot-password",       # forgot password
    "/forgot-password/",      # forgot password

    # Profile / user data.
    "/profile/",              # Django-style profile
    "/profile",               # Flask insecure profile
    "/user/",                 # generic user detail
    "/user/profile",          # generic user profile
    "/users",                 # list of users
    "/users/",                # list of users (trailing slash)

    # Admin-style routes.
    "/dashboard/",            # overview/dashboard (Django-style)
    "/admin",                 # admin index
    "/admin/",                # admin index with slash
    "/admin/login",           # admin login
    "/admin/login/",          # admin login
    "/admin/dump_users",      # Flask insecure plaintext credential dump

    # Search / listing endpoints.
    "/search/",               # Django-style search endpoint
    "/search",                # Flask insecure search
    "/api/search",            # API search endpoint
    "/api/search/",           # API search endpoint
    "/api/items",             # generic items listing
    "/api/items/",            # generic items listing

    # API-style authentication.
    "/api/login",             # API login
    "/api/login/",            # API login
    "/api/auth",              # generic API auth
    "/api/auth/",             # generic API auth

    # Insecure Flask demo special endpoints.
    "/ping",                  # Flask insecure command injection endpoint
    "/debug/load",            # Flask insecure pickle endpoint
]

# Simple patterns that often indicate server-side errors or stack traces.
ERROR_PATTERNS: List[str] = [
    "Traceback",
    "Exception",
    "django.db",
    "psycopg2",
    "OperationalError",
    "UNIQUE constraint failed",
    "TemplateSyntaxError",
    # Additional common error signatures.
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "AssertionError",
    "RuntimeError",
    "ImportError",
    "sqlite3.OperationalError",
    "werkzeug.exceptions",
    "Internal Server Error",
    "500 Internal Server Error",
]

# Simple mapping from anomaly reason labels to OWASP Top 10 style categories.
# This is intentionally approximate and intended for teaching/reporting rather
# than formal classification.
OWASP_REASON_MAP: Dict[str, List[str]] = {
    # Reflection of potentially malicious input back to the client.
    "reflected_payload": ["A03:2021-Injection (XSS)"],
    # Unhandled exceptions / 5xx responses and stack traces. Often indicate
    # both misconfiguration and weak error handling / monitoring.
    "5xx_error": [
        "A05:2021-Security Misconfiguration",
        "A09:2021-Security Logging and Monitoring Failures",
    ],
    "error_signature": [
        "A05:2021-Security Misconfiguration",
        "A09:2021-Security Logging and Monitoring Failures",
    ],
    # Unexpected 4xx errors can indicate broken access control or validation
    # gaps as well as misconfiguration.
    "client_error": [
        "A01:2021-Broken Access Control",
        "A05:2021-Security Misconfiguration",
    ],
    # Excessive redirects often come from misconfiguration or insecure design.
    "redirect_loop": [
        "A05:2021-Security Misconfiguration",
        "A04:2021-Insecure Design",
    ],
    # Very slow or very large responses can indicate insecure design or DoS
    # risk; they may also hint at fragile components and integrity issues.
    "slow_response": [
        "A04:2021-Insecure Design",
        "A08:2021-Software and Data Integrity Failures",
    ],
    "large_body": [
        "A04:2021-Insecure Design",
        "A08:2021-Software and Data Integrity Failures",
    ],
    
    "rate_limited": [],
    "pii_leak": ["A09:2021-Security Logging and Monitoring Failures"],
    "debug_info": ["A05:2021-Security Misconfiguration"],
    "missing_security_headers": ["A05:2021-Security Misconfiguration"],
    "weak_tls": ["A02:2021-Cryptographic Failures"],
    "cookie_issue": [
        "A02:2021-Cryptographic Failures",
        "A01:2021-Broken Access Control",
    ],
    "csrf_missing": [
        "A01:2021-Broken Access Control",
        "A05:2021-Security Misconfiguration",
    ],
    "open_redirect": ["A01:2021-Broken Access Control"],
    "idor_pattern": ["A01:2021-Broken Access Control"],
    "dir_listing": ["A05:2021-Security Misconfiguration"],
    "verbose_server_header": ["A05:2021-Security Misconfiguration"],
    "api_error_detail": [
        "A05:2021-Security Misconfiguration",
        "A09:2021-Security Logging and Monitoring Failures",
    ],
}

# Built-in payload categories used for targeted fuzzing. These are hard-coded
# so that the fuzzer has sensible defaults even without any external files.
PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    "sql": [
        "' OR '1'='1",
        "' OR 1=1 --",
        '" OR "1"="1" --',
        "admin'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; DROP TABLE users;--",
        # Extra SQLi-style patterns.
        "'; SELECT * FROM users;--",
        "' OR 'x'='x' /*",
        "'; UPDATE users SET is_admin=1 WHERE username='admin';--",
        "'; INSERT INTO users(username,password) VALUES('attacker','pass');--",
        "'; EXEC xp_cmdshell('whoami');--",
        "'; SELECT pg_sleep(5);--",
        "' AND 1=(SELECT COUNT(*) FROM users);--",
        "' UNION SELECT username, password FROM users--",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        '\"><script>alert(1)</script>',
        "<svg/onload=alert(1)>",
        "<body onload=alert('xss')>",
        # Extra XSS vectors.
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<details open ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<video src=x onerror=alert(1)></video>",
        "<math><mi xlink:href=\"javascript:alert(1)\"></mi></math>",
        "<object data=\"javascript:alert(1)\"></object>",
        "<form action=\"javascript:alert(1)\"><button>go</button></form>",
    ],
    "path": [
        "../etc/passwd",
        "../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "/../../../../../../etc/shadow",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
     
        "../../../../../../../../var/www/html/index.php",
        "..\\..\\..\\..\\..\\boot.ini",
        "../../../.ssh/id_rsa",
        "../../../../../../../../etc/hosts",
        "..%2F..%2F..%2F..%2F..%2Fconfig.php",
        "/..;/..;/..;/windows/win.ini",
        "..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    ],
    "unicode": [
        "测试",
        "áéíóúÁÉÍÓÚ",
        "😀😃😄😁😆😅😂🤣",
        "\u202eevil.exe",
        "null-byte-\u0000-test",
       
        "𝔘𝔫𝔦𝔠𝔬𝔡𝔢𝔖𝔱𝔯𝔦𝔫𝔤",
        "قائمة",
        "русский-текст",
        "हिन्दी-पाठ",
        "日本語テキスト",
        "δοκιμή-κειμένου",
        "Z̵͙͇̠͕̼̟͉̳̺̹͍̙͑ͬͫͥͨͨ͒͒̈́ͯ͑͆A͎̗̰̠̲̩͇̠͔̗̦̮̟͙͙̒ͫ̓͛ͦͣ͒ͯͫ͑͊͊ͯ̐ͭͮ͜ͅḺ̡̪̘̪̥͓̲̺̪̘̲̙͉̟̽͑ͯ̑͑ͬ̋̎ͭͅG̡̖͕̮̟̤͔̮̤̞ͯͪ͛ͦ̿̐̋͑̽ͧ͂ͯ͞Ȍ̡̮̙̮̝̏͂̽͌ͩ͒͊͊̚͢",
        "\u2066LTR\u2069\u2067RTL\u2069",
    ],
    "django": [
        "{{7*7}}",
        "{% debug %}",
        "{% load static %}",
        "{% if 1 %}test{% endif %}",
        "{{ request.user.username }}",
        "{{ settings.SECRET_KEY }}",
       
        "{{ request.META }}",
        "{{ ''.__class__.__mro__[2].__subclasses__() }}",
        "{{ config.items() }}",
        "{{ url_for('index') }}",
        "{% for k,v in request.META.items %}{{k}}={{v}}{% endfor %}",
        "{{ __import__('os').environ }}",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    ],
    # Flask / generic Python web patterns useful for SSTI-style tests and
    # misconfigured Jinja contexts.
    "flask": [
        "{{ config }}",
        "{{ request.headers }}",
        "{{ request.cookies }}",
        "{{ url_for('static', filename='app.py') }}",
        "{{ self.__class__.__mro__ }}",
        "{{ cycler.__init__.__globals__ }}",
        "{{ joiner.__init__.__globals__ }}",
        "{{ (''.__class__.__mro__[1].__subclasses__()) }}",
        "{{ request.environ }}",
        "{{ get_flashed_messages() }}",
    ],
}


def load_kv_json(path: Optional[str], label: str) -> Dict[str, str]:
    """
    Load a simple key/value mapping from a JSON file.

    The file is expected to contain a JSON object, for example:

    {
      "X-API-Key": "static-or-<fuzz>",
      "X-Trace-Id": "<fuzz>"
    }

    Any ``<fuzz>`` placeholder in the values will be replaced with the current
    payload string at request time.
    """
    if not path:
        return {}

    p = Path(path)
    if not p.exists():
        print(f"[!] {label} file '{path}' does not exist; ignoring.")
        return {}

    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Failed to load {label} file '{path}': {exc}; ignoring.")
        return {}

    if not isinstance(data, dict):
        print(f"[!] {label} file '{path}' did not contain a JSON object; ignoring.")
        return {}

    return {str(k): str(v) for k, v in data.items()}


def load_payload_library() -> Dict[str, List[str]]:
    """
    Return the built-in structured payload categories.

    Categories include:
    - sql
    - xss
    - path
    - unicode
    - django
    - flask
    """
    return PAYLOAD_LIBRARY


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


# Wrap core helpers so that assigning them as class attributes in tests does not
# cause implicit ``self`` binding. Inside this module we continue to use them as
# usual, and external callers (including the tests) see a normal callable.
_load_payload_library_impl = load_payload_library
_build_bodies_impl = build_bodies
_build_files_impl = build_files

load_payload_library = _HelperCallable(_load_payload_library_impl)
build_bodies = _HelperCallable(_build_bodies_impl)
build_files = _HelperCallable(_build_files_impl)


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


def _mut_invert_case(payload: str) -> str:
    return "".join(
        c.lower() if c.isupper() else c.upper() if c.islower() else c
        for c in payload
    )


def _mut_duplicate(payload: str) -> str:
    idx = random.randrange(len(payload))
    return payload[:idx] + payload[idx] * 2 + payload[idx + 1 :]


def _mut_delete(payload: str) -> str:
    if len(payload) <= 1:
        return payload
    idx = random.randrange(len(payload))
    return payload[:idx] + payload[idx + 1 :]


def _mut_insert_special(payload: str) -> str:
    specials = "!@#$%^&*()[]{}<>?/\\|"
    idx = random.randrange(len(payload) + 1)
    ch = random.choice(specials)
    return payload[:idx] + ch + payload[idx:]


def _mut_reverse(payload: str) -> str:
    return payload[::-1]


MUTATOR_FUNCS: Dict[str, Callable[[str], str]] = {
    "invert_case": _mut_invert_case,
    "duplicate": _mut_duplicate,
    "delete": _mut_delete,
    "insert_special": _mut_insert_special,
    "reverse": _mut_reverse,
}


def mutate_payload(payload: str, strategy: Optional[str] = None) -> str:
    """
    Apply a simple mutation to a payload string.

    The goal is not to be exhaustive like AFL, but to introduce small,
    repeatable distortions that may trigger edge cases in parsers and
    validation logic. The optional ``strategy`` argument can be used to select
    a specific mutator; if omitted, one is chosen at random.
    """
    if not payload:
        return payload

    if not strategy:
        strategy = random.choice(list(MUTATOR_FUNCS.keys()))

    func = MUTATOR_FUNCS.get(strategy)
    if not func:
        return payload
    return func(payload)


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
    base_headers: Optional[Dict[str, str]] = None,
    base_cookies: Optional[Dict[str, str]] = None,
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
    samples: List[Dict[str, object]] = []
    durations: List[float] = []
    lengths: List[int] = []

    payload_library: Dict[str, List[str]] = {}
    if payload_category:
        payload_library = load_payload_library()
        if payload_category not in payload_library:
            print(
                f"[!] Payload category '{payload_category}' is not defined in "
                "the built-in payload library. Falling back to random strings."
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

        mutator_name: Optional[str] = None
        if mutate:
            # Select a specific mutator so we can record which strategy was used
            # for this payload in the samples and any derived corpus.
            mutator_name = random.choice(list(MUTATOR_FUNCS.keys()))
            base = mutate_payload(base, strategy=mutator_name)

        # Choose a parameter name that matches common patterns for the target
        # endpoint so that fuzzing is more effective against both the Django
        # and insecure Flask demo applications.
        lower_path = path.lower()
        if "ping" in lower_path:
            # Flask insecure /ping endpoint uses the 'host' parameter.
            param_name = "host"
        elif "debug" in lower_path:
            # Flask insecure /debug/load endpoint uses the 'data' parameter.
            param_name = "data"
        elif "search" in lower_path:
            param_name = "q"
        else:
            param_name = "q"

        params = {param_name: base}

        # Apply <fuzz> placeholder substitution for headers and cookies.
        headers: Optional[Dict[str, str]] = None
        cookies: Optional[Dict[str, str]] = None
        if base_headers:
            headers = {
                name: value.replace("<fuzz>", base) for name, value in base_headers.items()
            }
        if base_cookies:
            cookies = {
                name: value.replace("<fuzz>", base) for name, value in base_cookies.items()
            }

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
                start_ts = time.perf_counter()
                resp = client.request(
                    method,
                    url,
                    params=params,
                    json=effective_json,
                    data=form_body,
                    files=files,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify,
                )
                duration = time.perf_counter() - start_ts
                body_len = len(resp.content or b"")
                redirects = len(resp.history or [])

                # Basic error / anomaly signals
                status = resp.status_code
                is_5xx = 500 <= status < 600
                text_snippet = resp.text[:2000] if hasattr(resp, "text") else ""
                has_error_signature = any(pat in text_snippet for pat in ERROR_PATTERNS)

                # Reflection detection for XSS-style issues – only check for
                # reasonably short payloads to avoid excessive work.
                reflected = False
                if len(base) <= 200 and base in text_snippet:
                    reflected = True

                rate_limited = status == 429
                if rate_limited:
                    # Simple rate-limit awareness: back off briefly before the
                    # next request.
                    time.sleep(1.0)

                status_codes.append(status)
                durations.append(duration)
                lengths.append(body_len)

                samples.append(
                    {
                        "iteration": i,
                        "params": params,
                        "json": effective_json,
                        "data": form_body,
                        "has_file": bool(files),
                        "has_headers": bool(headers),
                        "has_cookies": bool(cookies),
                        "mutator": mutator_name,
                        "status_code": status,
                        "duration": duration,
                        "response_length": body_len,
                        "redirects": redirects,
                        "is_5xx": is_5xx,
                        "has_error_signature": has_error_signature,
                        "reflected": reflected,
                        "rate_limited": rate_limited,
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
                    "has_headers": bool(headers),
                    "has_cookies": bool(cookies),
                    "status_code": None,
                    "error": str(last_exc),
                }
            )

    print("[+] Fuzzing complete. Status code counts:")
    for code in sorted(set(status_codes)):
        print(f"    {code}: {status_codes.count(code)}")

    # Derive simple baselines for anomaly detection.
    avg_duration = sum(durations) / len(durations) if durations else None
    avg_length = sum(lengths) / len(lengths) if lengths else None

    for sample in samples:
        reasons: List[str] = []
        status = sample.get("status_code")
        duration = sample.get("duration")
        length = sample.get("response_length")
        redirects = sample.get("redirects", 0) or 0

        if isinstance(duration, (int, float)) and avg_duration and duration > avg_duration * 3:
            reasons.append("slow_response")
        if isinstance(length, int) and avg_length and length > avg_length * 4:
            reasons.append("large_body")
        if sample.get("is_5xx"):
            reasons.append("5xx_error")
        if sample.get("has_error_signature"):
            reasons.append("error_signature")
        if sample.get("rate_limited"):
            reasons.append("rate_limited")
        if sample.get("reflected"):
            reasons.append("reflected_payload")
        if redirects > 10:
            reasons.append("redirect_loop")

        # Treat 4xx other than 404 as potential anomalies/crashes as well.
        if isinstance(status, int) and status >= 400 and status not in (404, 429):
            reasons.append("client_error")

        if reasons:
            sample["anomaly"] = True
            sample["anomaly_reasons"] = reasons
            # Attach approximate OWASP Top 10 style categories for reporting.
            owasp_categories: List[str] = []
            for reason in reasons:
                for cat in OWASP_REASON_MAP.get(reason, []):
                    if cat not in owasp_categories:
                        owasp_categories.append(cat)
            if owasp_categories:
                sample["owasp_categories"] = sorted(owasp_categories)
        else:
            sample["anomaly"] = False

    # Print a short anomaly-centric summary to help quickly spot interesting
    # behaviour without having to open the JSON/Excel reports.
    total_samples = len(samples)
    anomalous_samples = [s for s in samples if s.get("anomaly")]
    total_anomalous = len(anomalous_samples)
    if total_samples:
        pct = (total_anomalous / total_samples) * 100
    else:
        pct = 0.0

    print("\n[+] Anomaly summary")
    print(f"    Total samples: {total_samples}")
    print(f"    Anomalous samples: {total_anomalous} ({pct:.1f}%)")

    # Count anomaly reasons across all anomalous samples.
    reason_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    for s in anomalous_samples:
        for reason in s.get("anomaly_reasons", []):
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            for cat in OWASP_REASON_MAP.get(reason, []):
                category_counts[cat] = category_counts.get(cat, 0) + 1

    if reason_counts:
        print("    Reasons:")
        for reason, count in sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"      - {reason}: {count}")
    else:
        print("    (no anomalies detected)")

    if category_counts:
        print("    OWASP Top 10 signals:")
        for cat, count in sorted(
            category_counts.items(), key=lambda kv: (-kv[1], kv[0])
        ):
            print(f"      - {cat}: {count}")

    # Simple input/feature coverage-style summary.
    if samples:
        with_files = sum(1 for s in samples if s.get("has_file"))
        with_headers = sum(1 for s in samples if s.get("has_headers"))
        with_cookies = sum(1 for s in samples if s.get("has_cookies"))

        print("\n[+] Input coverage summary")
        print(f"    Requests with file uploads: {with_files}/{total_samples}")
        print(f"    Requests with custom headers: {with_headers}/{total_samples}")
        print(f"    Requests with custom cookies: {with_cookies}/{total_samples}")

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
        logs_dir = LOGS_ROOT
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"fuzz_{safe_host}_{safe_path}_{date_str}{mode_suffix}{category_suffix}.log"

        # If no JSON directory was provided, default to logs/json_logs.
        if output_json is None:
            output_dir = LOGS_ROOT / "json_logs"
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

        # Derive a small "interesting input" corpus based on anomalies so it can
        # be reused in future runs or inspected independently of the full log.
        interesting_inputs: List[Dict[str, Any]] = []
        for s in samples:
            if not s.get("anomaly"):
                continue
            params = s.get("params") or {}
            interesting_inputs.append(
                {
                    "payload": params.get("q"),
                    "mutator": s.get("mutator"),
                    "reasons": s.get("anomaly_reasons", []),
                    "owasp_categories": s.get("owasp_categories", []),
                    "status_code": s.get("status_code"),
                }
            )

        if interesting_inputs:
            corpus_path = output_dir / (
                f"fuzz_corpus_{safe_host}_{safe_path}_{date_str}"
                f"{mode_suffix}{category_suffix}.json"
            )
            corpus_doc = {
                "base_url": base_url,
                "path": path,
                "generated_at": datetime.now().isoformat(),
                "inputs": interesting_inputs,
            }
            corpus_path.write_text(json.dumps(corpus_doc, indent=2))
            print(f"[+] Interesting input corpus written to {corpus_path}")

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
        choices=["sql", "xss", "path", "unicode", "django", "flask"],
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
        "--all-methods",
        action="store_true",
        help=(
            "When set, fuzz each path with all standard HTTP methods "
            "(GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD) instead of "
            "only the single method specified by --method."
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
        "--headers-file",
        default=None,
        help=(
            "Optional JSON file containing base HTTP headers. Values may "
            "include the placeholder '<fuzz>', which will be replaced with "
            "the current payload string for each request."
        ),
    )
    parser.add_argument(
        "--cookies-file",
        default=None,
        help=(
            "Optional JSON file containing base cookies. Values may include "
            "the placeholder '<fuzz>', which will be replaced with the "
            "current payload string for each request."
        ),
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
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of worker threads to use for concurrent fuzzing (default: 1).",
    )
    parser.add_argument(
        "--replay",
        default=None,
        help="Path to a fuzz JSON report to replay exactly.",
    )
    parser.add_argument(
        "--replay-mutate",
        default=None,
        help="Path to a fuzz JSON report to replay with additional mutation applied.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help=(
            "Only print console summaries (status/anomalies); do not write "
            "JSON/log/Excel artefacts."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # --target is a user-friendly alias for --base-url.
    if args.target:
        args.base_url = args.target

    # Full automatic mode turns on a rich combination of features suitable for
    # demonstrations: both payload modes, all categories, all HTTP methods,
    # mutation, and file uploads across all AUTO_PATHS.
    if args.auto:
        args.mode = "auto"
        args.all_categories = True
        args.mutate_payloads = True
        args.fuzz_files = True
        args.all_methods = True
        print(
            "[*] Full auto mode enabled: mode=auto, all payload categories, "
            "all HTTP methods, payload mutation, and file upload fuzzing "
            "across AUTO_PATHS."
        )

    output_json = Path(args.output_json) if args.output_json else None
    base_headers = load_kv_json(args.headers_file, label="headers")
    base_cookies = load_kv_json(args.cookies_file, label="cookies")

    # If replay is requested, skip normal fuzzing and just resend requests
    # recorded in a previous JSON report.
    if args.replay or args.replay_mutate:
        report_path = args.replay_mutate or args.replay
        mutate = bool(args.replay_mutate)
        if not report_path:
            print("[!] --replay/--replay-mutate requires a JSON path.")
            return

        p = Path(report_path)
        if not p.exists():
            print(f"[!] Replay JSON file '{report_path}' does not exist.")
            return

        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[!] Failed to parse replay JSON '{report_path}': {exc}")
            return

        # Support both aggregate JSON (with "runs") and single-run JSON.
        runs = payload.get("runs")
        if not isinstance(runs, list):
            runs = [payload]

        client = requests.Session()
        verify = not args.insecure
        print(f"[*] Replaying {len(runs)} run(s) from {report_path} (mutate={mutate})")

        for run in runs:
            base_url = str(run.get("base_url", args.base_url))
            path = str(run.get("path", args.path))
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            print(f"[+] Replaying run for {url}")

            for sample in run.get("samples", []):
                original = sample.get("params", {}).get("q", "")
                if not isinstance(original, str):
                    continue
                payload_str = mutate_payload(original) if mutate else original
                params = {"q": payload_str}

                json_body, form_body = build_bodies(
                    payload=payload_str,
                    body_type=args.body_type,
                )
                files = build_files(payload_str, enable_files=args.fuzz_files)
                effective_json = None if files else json_body

                headers: Optional[Dict[str, str]] = None
                cookies: Optional[Dict[str, str]] = None
                if base_headers:
                    headers = {
                        name: value.replace("<fuzz>", payload_str)
                        for name, value in base_headers.items()
                    }
                if base_cookies:
                    cookies = {
                        name: value.replace("<fuzz>", payload_str)
                        for name, value in base_cookies.items()
                    }

                try:
                    resp = client.request(
                        args.method,
                        url,
                        params=params,
                        json=effective_json,
                        data=form_body,
                        files=files,
                        headers=headers,
                        cookies=cookies,
                        timeout=args.timeout,
                        verify=verify,
                    )
                    print(
                        f"  - Replayed iteration {sample.get('iteration')} -> "
                        f"status {resp.status_code}"
                    )
                except requests.RequestException as exc:
                    print(
                        f"  ! Replay error at iteration {sample.get('iteration')}: {exc}"
                    )

        return
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

    # Build a list of (path, category) jobs.
    jobs: List[Tuple[str, Optional[str]]] = [
        (p, c) for p in paths for c in categories
    ]

    def run_job(job: Tuple[str, Optional[str]]) -> None:
        path, category = job
        print(f"[*] Fuzzing path: {path}")
        if category:
            print(f"[*] Using payload category: {category}")

        # Decide which HTTP methods to use for this job.
        methods: List[str]
        if getattr(args, "all_methods", False):
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        else:
            methods = [args.method]

        # In mode=auto we run *both* random and buffer_overflow fuzzing.
        # When args.auto is set we only write aggregate outputs, not per-run
        # JSON/log files. In summary-only mode we suppress all file outputs.
        write_files = (not args.auto) and (not args.summary_only)

        for http_method in methods:
            print(f"[*] Using HTTP method: {http_method}")

            if args.mode == "auto":
                output_dir = output_json
                print("[*] Auto mode: running random fuzzing first...")
                fuzz_endpoint(
                    args.base_url,
                    path,
                    args.iterations,
                    output_json=output_dir,
                    payload_mode="random",
                    method=http_method,
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
                    base_headers=base_headers,
                    base_cookies=base_cookies,
                )
                print("[*] Auto mode: running buffer_overflow fuzzing...")
                fuzz_endpoint(
                    args.base_url,
                    path,
                    args.iterations,
                    output_json=output_dir,
                    payload_mode="buffer_overflow",
                    method=http_method,
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
                    base_headers=base_headers,
                    base_cookies=base_cookies,
                )
            else:
                fuzz_endpoint(
                    args.base_url,
                    path,
                    args.iterations,
                    output_json=output_json,
                    payload_mode=args.mode,
                    method=http_method,
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
                    base_headers=base_headers,
                    base_cookies=base_cookies,
                )

    if args.threads > 1 and len(jobs) > 1:
        print(f"[*] Running fuzzing with {args.threads} worker threads...")
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            list(executor.map(run_job, jobs))
    else:
        for job in jobs:
            run_job(job)

    # If we have collected aggregate data (full auto mode), emit combined JSON,
    # log and an Excel workbook with one sheet per run (unless summary-only).
    if aggregate_runs and not args.summary_only:
        parsed = urlparse(args.base_url)
        host = parsed.netloc or parsed.path or "unknown"
        safe_host = host.replace(":", "_").replace(".", "_")
        date_str = datetime.now().strftime("%d%m%y")

        aggregate_dir = LOGS_ROOT / "json_logs"
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
        log_dir = LOGS_ROOT
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

       
        try:
            from openpyxl import Workbook  # type: ignore

            excel_dir = LOGS_ROOT / "excel"
            excel_dir.mkdir(parents=True, exist_ok=True)
            excel_path = excel_dir / f"fuzz_all_{safe_host}_{date_str}.xlsx"

            wb = Workbook()
            first_sheet = True
            # Use the host (URL/IP) as the base worksheet title,
            
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

#James Scott (sba24070)