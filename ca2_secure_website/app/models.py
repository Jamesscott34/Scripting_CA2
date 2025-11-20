"""Database models for the CA2 banking app (to be expanded in later steps)."""

from django.conf import settings
from django.db import models


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


