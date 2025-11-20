"""Views for the CA2 banking app with secure / insecure teaching modes."""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from .forms import RegisterForm
from .models import BankAccount, Transaction


def _get_or_create_primary_account(user):
    """Helper to ensure each user has at least one demo account."""

    account = user.accounts.first()
    if account is None:
        account = BankAccount.objects.create(
            owner=user,
            iban=f"DEMO-{user.id:06d}",
            balance=1000,
        )
        Transaction.objects.create(
            account=account,
            amount=1000,
            description="Initial deposit",
        )
    return account


def register(request: HttpRequest) -> HttpResponse:
    """
    User registration view.

    In secure mode this behaves normally. In insecure mode we still keep the
    same logic but you can discuss what *could* be weakened (e.g. password
    policy) during the demonstration.
    """

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            _get_or_create_primary_account(user)
            raw_password = form.cleaned_data.get("password1")
            auth_user = authenticate(username=user.username, password=raw_password)
            if auth_user:
                login(request, auth_user)
                messages.success(request, "Account created successfully.")
                return redirect("dashboard")
    else:
        form = RegisterForm()
    return render(request, "registration/register.html", {"form": form})


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    account = _get_or_create_primary_account(request.user)
    transactions = account.transactions.all()[:10]
    context = {"account": account, "transactions": transactions}
    return render(request, "app/dashboard.html", context)


@login_required
def profile(request: HttpRequest) -> HttpResponse:
    return render(request, "app/profile.html")


@login_required
def search(request: HttpRequest) -> HttpResponse:
    """
    Simple search view demonstrating secure vs insecure query patterns.

    - In SECURE mode, we use parameterised ORM filtering.
    - In INSECURE mode, we use a raw query constructed from user input.
    """

    query = request.GET.get("q", "")
    results = []

    if query:
        account = _get_or_create_primary_account(request.user)
        if settings.SECURE_MODE == "secure":
            results = list(
                account.transactions.filter(description__icontains=query)[:20]
            )
        else:
            # INTENTIONALLY INSECURE EXAMPLE – do NOT copy to real systems.
            from django.db import connection

            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    SELECT id, amount, description, created_at
                    FROM app_transaction
                    WHERE account_id = %s AND description LIKE '%%{query}%%'
                    ORDER BY created_at DESC
                    LIMIT 20
                    """,
                    [account.id],
                )
                rows = cursor.fetchall()
            results = [
                {
                    "id": row[0],
                    "amount": row[1],
                    "description": row[2],
                    "created_at": row[3],
                }
                for row in rows
            ]

    context = {"query": query, "results": results}
    return render(request, "app/search.html", context)

