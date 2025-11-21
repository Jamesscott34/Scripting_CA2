FROM python:3.13-slim AS builder

WORKDIR /build

COPY ca2_secure_website/requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
 && pip install --upgrade pip \
 && pip wheel --no-cache-dir --no-deps -r requirements.txt -w wheels \
 && apt-get purge -y build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*


FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    dumb-init \
    curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/*

COPY ca2_secure_website /app

ARG SECURE_MODE=secure
ENV SECURE_MODE=${SECURE_MODE} \
    DJANGO_SETTINGS_MODULE=project.settings

# Collect static files for production (ignore errors in dev-like setups).
RUN python manage.py collectstatic --noinput || true

RUN adduser --disabled-password --gecos '' django \
 && chown -R django:django /app

USER django

EXPOSE 8000

HEALTHCHECK CMD curl -f http://localhost:8000/ || exit 1

ENTRYPOINT ["dumb-init", "--"]

CMD ["gunicorn", "project.wsgi:application", "--bind", "0.0.0.0:8000", "--workers=3", "--threads=2"]


