"""Custom template context processors for the CA2 banking app."""

from django.conf import settings


def security_mode(request):
    """
    Expose the current security mode to all templates.

    SECURE_MODE comes from Django settings and is driven by the environment
    variable of the same name (see project.settings and CA2.yaml).
    """

    return {"SECURE_MODE": settings.SECURE_MODE}


