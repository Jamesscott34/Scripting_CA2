"""Create a superuser and demo banking users for the CA2 project."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from app.models import BankAccount, Transaction


class Command(BaseCommand):
    help = "Create a superuser and named demo users with bank accounts/transactions."

    def handle(self, *args, **options):
        User = get_user_model()

        # Superuser
        admin_username = "admin_james"
        admin_password = "AdminJames123!"
        admin_email = "admin.james@example.com"

        if not User.objects.filter(username=admin_username).exists():
            self.stdout.write(f"Creating superuser '{admin_username}'...")
            User.objects.create_superuser(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                first_name="James",
                last_name="Admin",
            )
        else:
            self.stdout.write(f"Superuser '{admin_username}' already exists.")

        # Named demo users
        demo_users = [
            ("james", "James", "Smith", "james@example.com"),
            ("mark", "Mark", "Brown", "mark@example.com"),
            ("george", "George", "Johnson", "george@example.com"),
            ("mary", "Mary", "O'Neil", "mary@example.com"),
            ("sarah", "Sarah", "Lee", "sarah@example.com"),
        ]
        password = "UserDemo123!"

        for username, first_name, last_name, email in demo_users:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                },
            )
            if created:
                user.set_password(password)
                user.save()
                self.stdout.write(
                    f"Created demo user '{username}' "
                    f"({first_name} {last_name}) with password '{password}'."
                )
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



