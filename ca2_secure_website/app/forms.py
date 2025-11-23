"""Forms for the CA2 banking app."""

from decimal import Decimal

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import BankAccount, SecurityConfig


class RegisterForm(UserCreationForm):
    """Simple user registration form extending Django's UserCreationForm."""

    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]


class TransferForm(forms.Form):
    """Transfer money between the current user's accounts."""

    from_account = forms.ModelChoiceField(
        queryset=BankAccount.objects.none(),
        label="From account",
    )
    to_account = forms.ModelChoiceField(
        queryset=BankAccount.objects.none(),
        label="To account",
    )
    amount = forms.DecimalField(
        max_digits=12,
        decimal_places=2,
        min_value=Decimal("0.01"),
    )
    description = forms.CharField(
        max_length=255,
        required=False,
        help_text="Optional description, e.g. 'Move to savings'.",
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        mine = BankAccount.objects.filter(owner=user)
        self.fields["from_account"].queryset = mine
        # Allow sending to any account in the system (including your own).
        self.fields["to_account"].queryset = BankAccount.objects.all()

    def clean(self):
        cleaned = super().clean()
        from_acc = cleaned.get("from_account")
        to_acc = cleaned.get("to_account")
        if from_acc and to_acc and from_acc == to_acc:
            self.add_error("to_account", "Choose a different destination account.")
        return cleaned


class SavingsPlanForm(forms.Form):
    """Simple savings planner used to drive a chart on the profile page."""

    monthly_income = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        min_value=Decimal("0.01"),
        label="Monthly income",
    )
    monthly_bills = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        min_value=Decimal("0.00"),
        label="Monthly bills & expenses",
    )
    goal_amount = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        min_value=Decimal("0.01"),
        label="Savings goal amount",
    )
    months = forms.IntegerField(
        required=False,
        min_value=1,
        label="Months (optional)",
        help_text="If left blank, we will calculate how many months are needed.",
    )

    def clean(self):
        cleaned = super().clean()
        income = cleaned.get("monthly_income") or Decimal("0")
        bills = cleaned.get("monthly_bills") or Decimal("0")
        if income <= bills:
            raise forms.ValidationError(
                "Monthly income must be greater than monthly bills to make savings."
            )
        return cleaned


class AdminUserCreateForm(UserCreationForm):
    """Simple form for admins to create new users from the custom admin page."""

    email = forms.EmailField(required=True)
    first_name = forms.CharField(required=False)
    last_name = forms.CharField(required=False)
    is_staff = forms.BooleanField(required=False, initial=False)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ["username", "email", "first_name", "last_name", "is_staff"]


class SecurityModeForm(forms.ModelForm):
    """Form used by admins to toggle secure / insecure mode."""

    class Meta:
        model = SecurityConfig
        fields = ["mode"]

# James Scott (sba24070)
