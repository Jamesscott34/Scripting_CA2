"""Basic tests for the CA2 banking app."""

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from .models import BankAccount, Transaction


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

