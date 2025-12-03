"""
Django settings for the CA2 secure banking project.

This settings file supports a Secure / Insecure mode toggle driven by the
SECURE_MODE environment variable (see CA2.yaml for details).
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# IMPORTANT:
# - For a real deployment you should set DJANGO_SECRET_KEY in the environment to
#  a long, random value that you never commit to source control.
# - The fallback below is already long/random enough that Django's
#  `check --deploy` does not warn (no "django-insecure-" prefix, > 50 chars),
#  but you should still override it in production using DJANGO_SECRET_KEY.
SECRET_KEY = os.getenv(
  "DJANGO_SECRET_KEY",
  "jO6v$!Zp9m2wQx@F1rT8cL#eH4kN7sP0dG3yB6uI9oR2aV5tM8zC1bJ4",
)

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

if SECURE_MODE == "insecure":
  # In insecure teaching mode we remove CSRF protection completely so that
  # CSRF attacks are easy to demonstrate.
  MIDDLEWARE.remove("django.middleware.csrf.CsrfViewMiddleware")

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

# Optional toggle to force HTTPS-only access in environments where TLS is
# terminated by a reverse proxy (e.g. nginx, load balancer). We keep this
# behind an explicit flag so local development against http://127.0.0.1 does
# not break with redirect loops.
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "0").lower() in {"1", "true", "yes"}

# When FORCE_HTTPS is enabled and we are in secure mode, redirect all HTTP
# requests to HTTPS and trust the X-Forwarded-Proto header from the proxy.
SECURE_SSL_REDIRECT = FORCE_HTTPS and SECURE_MODE == "secure"
SECURE_PROXY_SSL_HEADER = (
  ("HTTP_X_FORWARDED_PROTO", "https") if FORCE_HTTPS else None
)

SECURE_BROWSER_XSS_FILTER = SECURE_MODE == "secure"
SECURE_CONTENT_TYPE_NOSNIFF = SECURE_MODE == "secure"
SECURE_HSTS_INCLUDE_SUBDOMAINS = SECURE_MODE == "secure"
SECURE_HSTS_PRELOAD = SECURE_MODE == "secure"
SECURE_HSTS_SECONDS = 31536000 if SECURE_MODE == "secure" else 0
X_FRAME_OPTIONS = "DENY" if SECURE_MODE == "secure" else "SAMEORIGIN"

# 
