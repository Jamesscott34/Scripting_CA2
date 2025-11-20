"""Custom template context processors for the CA2 banking app."""

from django.conf import settings

from .models import SecurityConfig


def security_mode(request):
    """
    Expose the current security mode to all templates.

    By default this is read from SecurityConfig (toggle in admin UI). If that
    table does not exist yet, fall back to the SECURE_MODE environment / setting.
    """

    try:
        mode = SecurityConfig.get_solo().mode
    except Exception:
        mode = settings.SECURE_MODE

    return {"SECURE_MODE": mode}

