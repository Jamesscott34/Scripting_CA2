#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Secure Programming & Scripting – CA2 bootstrap script
#
# This script sets up a virtual environment, installs dependencies for the
# Django project and security tooling, and applies initial database migrations.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
###############################################################################

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"

echo "[*] Creating virtual environment in ${VENV_DIR} (if not present)..."
python3 -m venv "${VENV_DIR}"

echo "[*] Activating virtual environment..."
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

echo "[*] Upgrading pip..."
pip install --upgrade pip

echo "[*] Installing root requirements..."
pip install -r "${PROJECT_ROOT}/requirements.txt"

echo "[*] Installing Django app requirements..."
pip install -r "${PROJECT_ROOT}/ca2_secure_website/requirements.txt"

echo "[*] Installing security tooling (Bandit, requests, ZAP client)..."
pip install bandit requests python-owasp-zap-v2.4

echo "[*] Applying initial Django migrations and seeding demo data (SQLite)..."
cd "${PROJECT_ROOT}/ca2_secure_website"
python manage.py makemigrations app
python manage.py migrate
python manage.py seed_demo_data

echo "[*] Running Django tests in SECURE mode..."
USE_SQLITE=1 SECURE_MODE=secure python manage.py test

echo "[*] Running Django tests in INSECURE mode (Task 2 integration uses TEST_MODE)..."
USE_SQLITE=1 SECURE_MODE=insecure TEST_MODE=insecure python manage.py test

echo "[*] Building and starting Docker environment..."
cd "${PROJECT_ROOT}/docker"
docker compose up -d --build

echo "[*] Running Django tests inside Docker (secure and insecure)..."
docker compose run --rm -e SECURE_MODE=secure web python manage.py test
docker compose run --rm -e SECURE_MODE=insecure web python manage.py test

echo "[*] Stopping Docker containers and cleaning volumes..."
docker compose down -v

echo "[*] All setup, tests, and Docker checks completed successfully."
echo "[*] To run the app locally (outside Docker) in secure mode:"
echo "    cd \"${PROJECT_ROOT}/ca2_secure_website\" && USE_SQLITE=1 SECURE_MODE=secure python manage.py runserver 127.0.0.1:8001"

