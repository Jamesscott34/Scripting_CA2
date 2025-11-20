"""
Django settings for the CA2 secure banking project.

This settings file supports a Secure / Insecure mode toggle driven by the
SECURE_MODE environment variable (see CA2.yaml for details).
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "insecure-development-key")

DEBUG = os.getenv("DJANGO_DEBUG", "False").lower() in {"1", "true", "yes"}

SECURE_MODE = os.getenv("SECURE_MODE", "secure").lower()

# Optional override to use SQLite for local development instead of PostgreSQL.
USE_SQLITE = os.getenv("USE_SQLITE", "0").lower() in {"1", "true", "yes"}

ALLOWED_HOSTS: list[str] = [
    h.strip()
    for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "app",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "app" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "app.context_processors.security_mode",
            ],
        },
    },
]

WSGI_APPLICATION = "project.wsgi.application"
ASGI_APPLICATION = "project.asgi.application"

if USE_SQLITE:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "ca2_bank"),
            "USER": os.getenv("POSTGRES_USER", "ca2_user"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", "changeme"),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

SESSION_COOKIE_SECURE = SECURE_MODE == "secure"
CSRF_COOKIE_SECURE = SECURE_MODE == "secure"
# In real production you'd terminate HTTPS in a reverse proxy and keep this on;
# for the CA2 teaching project we disable automatic HTTPS redirects so the
# built-in dev server can be used over plain HTTP.
SECURE_SSL_REDIRECT = False
SECURE_BROWSER_XSS_FILTER = SECURE_MODE == "secure"
SECURE_CONTENT_TYPE_NOSNIFF = SECURE_MODE == "secure"
SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_MODE == "secure"
SECURE_HSTS_PRELOAD = SECURE_MODE == "secure"
SECURE_HSTS_SECONDS = 31536000 if SECURE_MODE == "secure" else 0
X_FRAME_OPTIONS = "DENY" if SECURE_MODE == "secure" else "SAMEORIGIN"


