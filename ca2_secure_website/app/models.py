"""Database models for the CA2 banking app (to be expanded in later steps)."""

from django.conf import settings
from django.db import models


class SecurityConfig(models.Model):
    """Stores the current secure / insecure teaching mode, editable from the UI."""

    MODE_SECURE = "secure"
    MODE_INSECURE = "insecure"

    mode = models.CharField(
        max_length=10,
        choices=[
            (MODE_SECURE, "Secure"),
            (MODE_INSECURE, "Insecure"),
        ],
        default=MODE_SECURE,
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Security mode: {self.mode}"

    @classmethod
    def get_solo(cls) -> "SecurityConfig":
        obj, _ = cls.objects.get_or_create(pk=1, defaults={"mode": cls.MODE_SECURE})
        return obj


class BankAccount(models.Model):
    """Simple representation of a user's bank account."""

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="accounts",
    )
    name = models.CharField(max_length=50, default="Current Account")
    iban = models.CharField(max_length=34, unique=True)
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.owner.username} – {self.name} ({self.iban})"


class Transaction(models.Model):
    """Minimal transaction model, suitable for demo purposes."""

    account = models.ForeignKey(
        BankAccount,
        on_delete=models.CASCADE,
        related_name="transactions",
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.amount} on {self.account.iban}"


