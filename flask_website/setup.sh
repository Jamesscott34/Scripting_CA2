#!/usr/bin/env bash
set -euo pipefail

# Simple one-command setup for the Flask demo apps.
#
# This script:
#  - Creates a Python virtual environment in ./flask_website/.venv
#  - Installs dependencies from ./flask_website/requirements.txt
#  - Starts BOTH Flask servers on separate ports:
#    - insecure_flask_app on port 5000
#    - secure_flask_app  on port 5001

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

echo "[+] Flask setup starting in $ROOT_DIR"

if [ ! -d "$VENV_DIR" ]; then
 echo "[+] Creating virtual environment in $VENV_DIR"
 python3 -m venv "$VENV_DIR"
else
 echo "[*] Reusing existing virtual environment in $VENV_DIR"
fi

echo "[+] Upgrading pip and installing dependencies from flask_website/requirements.txt"
"$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
"$VENV_DIR/bin/pip" install -r "$ROOT_DIR/requirements.txt" >/dev/null

echo "[+] Dependencies installed."

INSECURE_APP="$ROOT_DIR/insecure_flask_app/app.py"
SECURE_APP="$ROOT_DIR/secure_flask_app/app.py"

if [ ! -f "$INSECURE_APP" ] || [ ! -f "$SECURE_APP" ]; then
 echo "[!] Could not find Flask app entrypoints:"
 echo "  insecure: $INSECURE_APP"
 echo "  secure:  $SECURE_APP"
 exit 1
fi

echo "[+] Starting insecure Flask app on http://127.0.0.1:5000 ..."
"$VENV_DIR/bin/python" "$INSECURE_APP" >/dev/null 2>&1 &
INSECURE_PID=$!

echo "[+] Starting secure Flask app on http://127.0.0.1:5001 ..."
SECURE_FLASK_SECRET=${SECURE_FLASK_SECRET:-"change-me-to-a-long-random-value"}
SECURE_FLASK_SECRET="$SECURE_FLASK_SECRET" \
 "$VENV_DIR/bin/python" "$SECURE_APP" >/dev/null 2>&1 &
SECURE_PID=$!

echo
echo "[+] Both Flask apps are starting in the background:"
echo "  Insecure app PID: $INSECURE_PID (port 5000)"
echo "  Secure app PID: $SECURE_PID  (port 5001)"
echo
echo "To stop them later, you can run:"
echo " kill $INSECURE_PID $SECURE_PID"
echo
echo "Or find them with:"
echo " ps aux | grep app.py"
echo

# 
