"""Basic tests for the CA2 banking app."""

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse


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
