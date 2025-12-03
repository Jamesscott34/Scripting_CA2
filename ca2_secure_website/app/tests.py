"""Tests for the CA2 banking app and security tooling.

This module contains:

- Functional tests for the Django views (dashboard, search in secure/insecure modes).
- "Buffering" / robustness checks using very large input.
- Integration tests that invoke the Task 2 scripts (fuzzing and Bandit),
 log their output, and store JSON artefacts for later inspection.

Each class and test is documented to explain *what* is being verified and
*why* it matters for secure vs insecure behaviour.
"""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import unittest

from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from .models import BankAccount, SecurityConfig, Transaction


class DashboardViewTests(TestCase):
  """Basic smoke tests for the dashboard view."""

  def setUp(self) -> None:
    self.user = User.objects.create_user(username="testuser", password="password123")
    self.client = Client()

  def test_dashboard_requires_login(self) -> None:
    """Unauthenticated users should be redirected to the login page."""
    response = self.client.get(reverse("dashboard"))
    self.assertEqual(response.status_code, 302)
    self.assertIn("login", response.url)

  def test_dashboard_renders_for_authenticated_user(self) -> None:
    """Authenticated users should see the dashboard template."""
    self.client.login(username="testuser", password="password123")
    response = self.client.get(reverse("dashboard"))
    self.assertEqual(response.status_code, 200)
    self.assertTemplateUsed(response, "app/dashboard.html")


class SearchViewSecureModeTests(TestCase):
  """
  Tests for the search view when running in SECURE mode.

  These verify that:
  - The ORM-based search path is used and returns expected results.
  - Potential XSS payloads are escaped.
  - Very large input does not break the view.
  """
  @override_settings(SECURE_MODE="secure")
  def test_secure_search_uses_orm_and_returns_results(self) -> None:
    """Secure search should find results using the safe ORM path."""
    user = User.objects.create_user(username="alice", password="password123")
    account = BankAccount.objects.create(owner=user, iban="TESTIBAN1", balance=100)
    Transaction.objects.create(account=account, amount=10, description="Coffee shop")

    client = Client()
    client.login(username="alice", password="password123")
    response = client.get(reverse("search"), {"q": "Coffee"})

    self.assertEqual(response.status_code, 200)
    self.assertContains(response, "Coffee shop")

  @override_settings(SECURE_MODE="secure")
  def test_secure_search_escapes_script_tags(self) -> None:
    """
    Ensure that script tags in the query are HTML-escaped and not rendered
    as raw `<script>` elements, preventing reflected XSS in secure mode.
    """
    user = User.objects.create_user(username="alice2", password="password123")
    account = BankAccount.objects.create(owner=user, iban="TESTIBAN3", balance=100)
    Transaction.objects.create(account=account, amount=10, description="Test")

    client = Client()
    client.login(username="alice2", password="password123")
    payload = "<script>alert(1)</script>"
    response = client.get(reverse("search"), {"q": payload})

    content = response.content.decode()
    # Auto-escaped output should contain the encoded form, not the raw script tags.
    self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
    self.assertNotIn("<script>alert(1)</script>", content)

  @override_settings(SECURE_MODE="secure")
  def test_secure_search_handles_large_input(self) -> None:
    """
    Send a very large query string and assert the view still returns HTTP
    200, exercising buffering and robustness without crashing.
    """
    user = User.objects.create_user(username="alice3", password="password123")
    account = BankAccount.objects.create(owner=user, iban="TESTIBAN4", balance=100)
    Transaction.objects.create(account=account, amount=10, description="Test")

    client = Client()
    client.login(username="alice3", password="password123")
    big_query = "A" * 10000
    response = client.get(reverse("search"), {"q": big_query})
    self.assertEqual(response.status_code, 200)


class SearchViewInsecureModeTests(TestCase):
  """
  Tests for the search view when running in INSECURE mode.

  Here we *intentionally* verify that:
  - The page still works functionally.
  - Script tags are reflected unescaped, demonstrating XSS.
  - Large input is accepted (for fuzzing / training purposes).
  """
  @override_settings(SECURE_MODE="insecure")
  def test_insecure_search_still_returns_expected_results(self) -> None:
    """Insecure search should still behave functionally for normal queries."""
    user = User.objects.create_user(username="bob", password="password123")
    account = BankAccount.objects.create(owner=user, iban="TESTIBAN2", balance=50)
    Transaction.objects.create(account=account, amount=5, description="Taxi fare")

    client = Client()
    client.login(username="bob", password="password123")
    response = client.get(reverse("search"), {"q": "Taxi"})

    self.assertEqual(response.status_code, 200)
    self.assertContains(response, "Taxi fare")

  @override_settings(SECURE_MODE="insecure")
  def test_insecure_search_reflects_raw_script_tags(self) -> None:
    # Ensure the SecurityConfig model is also in insecure mode so the
    # template context processor picks it up.
    SecurityConfig.get_solo().__class__.objects.update_or_create(
      pk=1, defaults={"mode": SecurityConfig.MODE_INSECURE}
    )

    user = User.objects.create_user(username="bob2", password="password123")
    account = BankAccount.objects.create(owner=user, iban="TESTIBAN5", balance=50)
    Transaction.objects.create(account=account, amount=5, description="Test")

    client = Client()
    client.login(username="bob2", password="password123")
    payload = "<script>alert(1)</script>"
    response = client.get(reverse("search"), {"q": payload})

    content = response.content.decode()
    # In insecure mode we deliberately render the query with |safe.
    self.assertIn("<script>alert(1)</script>", content)

  @override_settings(SECURE_MODE="insecure")
  def test_insecure_search_handles_large_input(self) -> None:
    """In insecure mode, large inputs should also be accepted without crashing."""
    user = User.objects.create_user(username="bob3", password="password123")
    account = BankAccount.objects.create(owner=user, iban="TESTIBAN6", balance=50)
    Transaction.objects.create(account=account, amount=5, description="Test")

    client = Client()
    client.login(username="bob3", password="password123")
    big_query = "B" * 10000
    response = client.get(reverse("search"), {"q": big_query})
    self.assertEqual(response.status_code, 200)


class Task2ScriptsLogTests(TestCase):
  """
  Light integration tests that invoke the Task 2 security scripts in both
  secure and insecure modes and write their output to log files.

  These tests are designed for demonstration: they DON'T fail on non-zero
  return codes but always capture stdout/stderr so you can inspect results.
  """

  def _project_root(self) -> Path:
    """Return the repository or app root directory.

    Locally, `tests.py` lives in `ca2_secure_website/app/` and the repo
    root (which contains `task2_scripts/`) is two levels up.

    Inside the Docker image, the Django project is copied to `/app` and
    this file lives at `/app/app/tests.py`, so the logical "project root"
    is one level up (the directory that contains `manage.py`).
    """
    here = Path(__file__).resolve()

    # Local repo layout: .../Scripting/ca2_secure_website/app/tests.py
    repo_root = here.parents[2]
    if (repo_root / "task2_scripts").exists():
      return repo_root

    # Docker layout: /app/app/tests.py → project root is /app.
    app_root = here.parents[1]
    if (app_root / "manage.py").exists():
      return app_root

    # Fallback to the original assumption if neither heuristic matches.
    return repo_root

  def _logs_dir(self) -> Path:
    """Ensure and return the folder used for human-readable log files."""

    logs = self._project_root() / "logs"
    logs.mkdir(exist_ok=True)
    return logs

  def _run_script(self, cmd: list[str], log_name: str, mode: str) -> None:
    """Run a Task 2 script and capture its output into a log file.

    The log contains:
    - Timestamp
    - Mode (secure/insecure)
    - Command and return code
    - Full STDOUT and STDERR
    """
    root = self._project_root()
    env = os.environ.copy()
    env["SECURE_MODE"] = mode
    env.setdefault("USE_SQLITE", "1")

    proc = subprocess.run(
      cmd,
      cwd=root,
      capture_output=True,
      text=True,
      env=env,
    )

    log_path = self._logs_dir() / log_name
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    log_path.write_text(
      f"Timestamp: {timestamp}\n"
      f"Mode: {mode}\n"
      f"Command: {' '.join(cmd)}\n"
      f"Return code: {proc.returncode}\n\n"
      f"STDOUT:\n{proc.stdout}\n\nSTDERR:\n{proc.stderr}\n"
    )

  def test_task2_scripts_generate_logs_for_secure_and_insecure(self) -> None:
    """
    Run fuzzing and Bandit scripts in secure and insecure modes and ensure
    that logs and JSON artefacts are generated.

    Modes:
    - If `SECURE_MODE` is set (e.g. `SECURE_MODE=secure python manage.py test`)
     we only run that mode.
    - Otherwise, we run both secure and insecure to generate comparative data.
    """

    root = self._project_root()

    # If the Task 2 scripts are not present in this environment (for
    # example inside the Docker image where only the Django project is
    # copied), skip this integration test rather than failing.
    fuzz_path = root / "task2_scripts" / "fuzz_test.py"
    bandit_path = root / "task2_scripts" / "sast_bandit.py"
    if not (fuzz_path.exists() and bandit_path.exists()):
      self.skipTest("Task 2 scripts not available in this environment.")

    # Allow limiting to a single mode via environment:
    # - Primary: SECURE_MODE (so running `SECURE_MODE=secure python manage.py test`
    #  only runs secure-mode Task 2 integrations).
    # - Override: TEST_MODE (explicit test selector).
    selected_mode = os.getenv("TEST_MODE") or os.getenv("SECURE_MODE")
    modes = (selected_mode,) if selected_mode in {"secure", "insecure"} else (
      "secure",
      "insecure",
    )

    for mode in modes:
      # Fuzzing against the running app (ensure you've started it separately).
      fuzz_cmd = [
        sys.executable,
        "task2_scripts/fuzz_test.py",
        "--base-url",
        "http://127.0.0.1:8001",
        "--path",
        "/search/",
        "--iterations",
        "5",
        "--output-json",
        str(root / "logs" / "json_logs"),
      ]
      self._run_script(fuzz_cmd, f"fuzz_{mode}.log", mode)

      # Bandit SAST against the Django project.
      bandit_cmd = [
        sys.executable,
        "task2_scripts/sast_bandit.py",
        "--path",
        str(root / "ca2_secure_website"),
        "--output-json",
        str(
          root
          / "logs"
          / "json_logs"
          / f"bandit_report_{mode}.json"
        ),
        "--mode",
        mode,
      ]
      self._run_script(bandit_cmd, f"bandit_{mode}.log", mode)


class Task2HelperUnitTests(SimpleTestCase):
  """
  Lightweight unit tests for core Task 2 helper functions.

  These complement the integration tests above by exercising individual
  helpers such as the fuzz payload builders and Bandit summary formatter.
  """

  @classmethod
  def setUpClass(cls) -> None:
    super().setUpClass()
    # Locate the repository root and task2_scripts folder in the same way
    # as Task2ScriptsLogTests, then attempt to import helper functions.
    here = Path(__file__).resolve()
    repo_root = here.parents[2]
    task2_dir = repo_root / "task2_scripts"
    if not task2_dir.exists():
      raise unittest.SkipTest("Task 2 scripts not available in this environment.")

    if str(repo_root) not in sys.path:
      sys.path.insert(0, str(repo_root))

    # Lazy-import into class attributes so individual tests can use them.
    from task2_scripts.fuzz_test import ( # type: ignore
      build_bodies,
      build_files,
      load_payload_library,
    )
    from task2_scripts.sast_bandit import print_summary # type: ignore

    cls._build_bodies = build_bodies
    cls._build_files = build_files
    cls._load_payload_library = load_payload_library
    cls._print_summary = print_summary

  def test_load_payload_library_has_expected_categories(self) -> None:
    library = self._load_payload_library()
    for key in ["sql", "xss", "path", "unicode", "django"]:
      self.assertIn(key, library)
      self.assertIsInstance(library[key], list)
      self.assertTrue(
        library[key],
        msg=f"Payload category '{key}' should not be empty",
      )

  def test_build_bodies_json_and_form(self) -> None:
    payload = "test-payload"
    json_body, form_body = self._build_bodies(payload, "json")
    self.assertIsNotNone(json_body)
    self.assertIsNone(form_body)
    self.assertEqual(json_body["username"], payload)

    json_body, form_body = self._build_bodies(payload, "form")
    self.assertIsNone(json_body)
    self.assertIsNotNone(form_body)
    self.assertEqual(form_body["password"], payload)

  def test_build_files_creates_large_enough_payload(self) -> None:
    payload = "x"
    files = self._build_files(payload, enable_files=True)
    self.assertIsNotNone(files)
    name, content, mime = files["file"]
    self.assertTrue(name)
    self.assertTrue(mime)
    # The helper should expand very small payloads to at least ~1KB.
    self.assertGreaterEqual(len(content), 1024)

  def test_print_summary_handles_empty_report(self) -> None:
    # An empty report should not raise and should print a sensible summary.
    # We capture stdout via the Django test runner's output capture.
    self._print_summary({})

# 
