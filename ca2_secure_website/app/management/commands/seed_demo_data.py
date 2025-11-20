"""Create a superuser and demo banking users for the CA2 project."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from app.models import BankAccount, Transaction


class Command(BaseCommand):
    help = "Create a superuser and demo users with bank accounts/transactions."

    def handle(self, *args, **options):
        User = get_user_model()

        # Superuser
        admin_username = "admin"
        admin_password = "AdminDemo123!"
        admin_email = "admin@example.com"

        if not User.objects.filter(username=admin_username).exists():
            self.stdout.write(f"Creating superuser '{admin_username}'...")
            User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
            )
        else:
            self.stdout.write(f"Superuser '{admin_username}' already exists.")

        # Demo users
        for i in range(1, 6):
            username = f"user{i}"
            email = f"user{i}@example.com"
            password = "UserDemo123!"

            user, created = User.objects.get_or_create(
                username=username,
                defaults={"email": email},
            )
            if created:
                user.set_password(password)
                user.save()
                self.stdout.write(f"Created demo user '{username}' with password '{password}'.")
            else:
                self.stdout.write(f"Demo user '{username}' already exists.")

            # Ensure each user has an account and a couple of transactions.
            account, _ = BankAccount.objects.get_or_create(
                owner=user,
                defaults={"iban": f"DEMO-{user.id:06d}", "balance": 1000},
            )
            if not account.transactions.exists():
                Transaction.objects.create(
                    account=account,
                    amount=250,
                    description="Salary payment",
                )
                Transaction.objects.create(
                    account=account,
                    amount=-45,
                    description="Grocery shopping",
                )

        self.stdout.write(self.style.SUCCESS("Demo data created successfully."))


