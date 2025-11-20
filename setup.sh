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

echo "[*] Installing root requirements (if any)..."
if [ -f "${PROJECT_ROOT}/requirements.txt" ]; then
  pip install -r "${PROJECT_ROOT}/requirements.txt"
fi

echo "[*] Installing Django app requirements..."
pip install -r "${PROJECT_ROOT}/ca2_secure_website/requirements.txt"

echo "[*] Installing security tooling (Bandit, requests, ZAP client)..."
pip install bandit requests python-owasp-zap-v2.4

echo "[*] Applying initial Django migrations..."
cd "${PROJECT_ROOT}/ca2_secure_website"
python manage.py migrate

echo "[*] Setup complete. You can now run the development server with:"
echo "    cd \"${PROJECT_ROOT}/ca2_secure_website\" && python manage.py runserver"


