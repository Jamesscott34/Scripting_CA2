#!/usr/bin/env bash
set -euo pipefail

# Simple one-command setup for the Flask demo apps.
#
# This script:
#   - Creates a Python virtual environment in ./flask/.venv
#   - Installs dependencies from ./flask/requirements.txt
# It does NOT start the servers automatically; see README.md for run commands.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

echo "[+] Flask setup starting in $ROOT_DIR"

if [ ! -d "$VENV_DIR" ]; then
  echo "[+] Creating virtual environment in $VENV_DIR"
  python3 -m venv "$VENV_DIR"
else
  echo "[*] Reusing existing virtual environment in $VENV_DIR"
fi

echo "[+] Upgrading pip and installing dependencies from flask/requirements.txt"
"$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
"$VENV_DIR/bin/pip" install -r "$ROOT_DIR/requirements.txt"

echo
echo "[+] Flask environment ready."
echo
echo "To run the apps using the virtualenv:"
echo
echo "  cd flask"
echo "  source .venv/bin/activate"
echo "  # Insecure app (port 5000)"
echo "  cd insecure_flask_app && python app.py"
echo
echo "  # Secure app (port 5001)"
echo "  cd ../secure_flask_app"
echo "  export SECURE_FLASK_SECRET=\"change-me-to-a-long-random-value\""
echo "  python app.py"
echo


