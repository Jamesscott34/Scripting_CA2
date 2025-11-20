"""Views for the CA2 banking app with secure / insecure teaching modes."""

import json
import math
from decimal import Decimal

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from .forms import RegisterForm, SavingsPlanForm, TransferForm
from .models import BankAccount, Transaction


def _ensure_demo_accounts(user):
    """
    Ensure each user has at least a main and savings account.

    This keeps the demo simple for transfers and savings examples.
    """

    main, _ = BankAccount.objects.get_or_create(
        owner=user,
        name="Current Account",
        defaults={
            "iban": f"DEMO-{user.id:06d}",
            "balance": 1000,
        },
    )
    if not main.transactions.exists():
        Transaction.objects.create(
            account=main,
            amount=1000,
            description="Initial deposit",
        )

    savings, _ = BankAccount.objects.get_or_create(
        owner=user,
        name="Savings Account",
        defaults={
            "iban": f"SAVE-{user.id:06d}",
            "balance": 0,
        },
    )
    return main, savings


def _get_primary_account(user):
    """Return the main current account (creating demo accounts if needed)."""

    main, _ = _ensure_demo_accounts(user)
    return main


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
            _ensure_demo_accounts(user)
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
    account = _get_primary_account(request.user)
    transactions = account.transactions.all()[:10]
    context = {"account": account, "transactions": transactions}
    return render(request, "app/dashboard.html", context)


@login_required
def profile(request: HttpRequest) -> HttpResponse:
    main, savings = _ensure_demo_accounts(request.user)
    accounts = BankAccount.objects.filter(owner=request.user)

    transfer_form = TransferForm(request.user, data=None)
    savings_form = SavingsPlanForm()
    savings_chart = None

    if request.method == "POST":
        if "transfer-submit" in request.POST:
            transfer_form = TransferForm(request.user, data=request.POST)
            if transfer_form.is_valid():
                from_acc = transfer_form.cleaned_data["from_account"]
                to_acc = transfer_form.cleaned_data["to_account"]
                amount: Decimal = transfer_form.cleaned_data["amount"]
                description = transfer_form.cleaned_data["description"]

                # Basic security checks in secure mode
                if settings.SECURE_MODE == "secure" and from_acc.balance < amount:
                    messages.error(request, "Insufficient funds for this transfer.")
                else:
                    from_acc.balance -= amount
                    to_acc.balance += amount
                    from_acc.save()
                    to_acc.save()
                    Transaction.objects.create(
                        account=from_acc,
                        amount=-amount,
                        description=description or f"Transfer to {to_acc.name}",
                    )
                    Transaction.objects.create(
                        account=to_acc,
                        amount=amount,
                        description=description or f"Transfer from {from_acc.name}",
                    )
                    messages.success(request, "Transfer completed.")
                    return redirect("profile")

        elif "savings-submit" in request.POST:
            savings_form = SavingsPlanForm(request.POST)
            if savings_form.is_valid():
                income = savings_form.cleaned_data["monthly_income"]
                bills = savings_form.cleaned_data["monthly_bills"]
                goal = savings_form.cleaned_data["goal_amount"]
                months = savings_form.cleaned_data.get("months")
                monthly_saving = income - bills

                if not months:
                    months = max(1, math.ceil(goal / monthly_saving))

                points = []
                balance = Decimal("0")
                for m in range(1, months + 1):
                    balance += monthly_saving
                    points.append({"month": m, "amount": float(balance)})

                savings_chart = {
                    "labels": [p["month"] for p in points],
                    "data": [p["amount"] for p in points],
                    "goal": float(goal),
                }

    context = {
        "accounts": accounts,
        "main_account": main,
        "savings_account": savings,
        "transfer_form": transfer_form,
        "savings_form": savings_form,
        "savings_chart_json": json.dumps(savings_chart) if savings_chart else None,
    }
    return render(request, "app/profile.html", context)


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
        account = _get_primary_account(request.user)
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

