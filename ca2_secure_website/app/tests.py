"""Tests for the CA2 banking app and security tooling."""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .models import BankAccount, SecurityConfig, Transaction


class DashboardViewTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(username="testuser", password="password123")
        self.client = Client()

    def test_dashboard_requires_login(self) -> None:
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_dashboard_renders_for_authenticated_user(self) -> None:
        self.client.login(username="testuser", password="password123")
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "app/dashboard.html")


class SearchViewSecureModeTests(TestCase):
    @override_settings(SECURE_MODE="secure")
    def test_secure_search_uses_orm_and_returns_results(self) -> None:
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
        user = User.objects.create_user(username="alice3", password="password123")
        account = BankAccount.objects.create(owner=user, iban="TESTIBAN4", balance=100)
        Transaction.objects.create(account=account, amount=10, description="Test")

        client = Client()
        client.login(username="alice3", password="password123")
        big_query = "A" * 10000
        response = client.get(reverse("search"), {"q": big_query})
        self.assertEqual(response.status_code, 200)


class SearchViewInsecureModeTests(TestCase):
    @override_settings(SECURE_MODE="insecure")
    def test_insecure_search_still_returns_expected_results(self) -> None:
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
        # tests.py lives in ca2_secure_website/app/, so the repo root is two levels up.
        return Path(__file__).resolve().parents[2]

    def _logs_dir(self) -> Path:
        logs = self._project_root() / "logs"
        logs.mkdir(exist_ok=True)
        return logs

    def _run_script(self, cmd: list[str], log_name: str, mode: str) -> None:
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
        root = self._project_root()

        # Allow limiting to a single mode via environment:
        # - Primary: SECURE_MODE (so running `SECURE_MODE=secure python manage.py test`
        #   only runs secure-mode Task 2 integrations).
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
                str(
                    root
                    / "logs"
                    / "json_logs"
                    / f"fuzz_results_{mode}.json"
                ),
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


