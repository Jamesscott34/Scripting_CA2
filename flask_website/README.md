## Flask Demo Apps – Insecure vs Secure

This folder contains two small Flask applications that mirror the core flows of
the Django CA2 banking site, but implemented as **standalone Flask demos** for
security training and tooling (SAST, DAST, fuzzing).

- `insecure_flask_app/` – intentionally vulnerable implementation.
- `secure_flask_app/` – hardened version of the same functionality.

Both apps use **SQLite** in their own folder (`insecure.db` / `secure.db`),
Jinja2 templates, and a small set of routes aligned with the Django app:

- `/` – dashboard (welcome + balance + recent transactions).
- `/register` – user registration.
- `/login` / `/logout` – authentication.
- `/profile` – simple account/profile page with a transaction/note form.
- `/search` – search a user's transactions.

The **root** `requirements.txt` is used for Docker builds; the containers then
install Flask (and Werkzeug for the secure app) on top. For local Flask-only
development this folder also contains its own `requirements.txt` which mirrors
the root file and adds Flask-specific dependencies.

---

### One-time setup for the Flask apps (virtualenv)

From the repository root:

```bash
cd flask_website
chmod +x setup.sh
./setup.sh
```

This will:

- Create a local virtualenv in `flask_website/.venv` (if it does not already exist).
- Install dependencies from `flask_website/requirements.txt`.

You can then either activate the environment:

```bash
cd flask_website
source .venv/bin/activate
```

or call the Python binary explicitly as shown below.

---

### Running locally (without Docker, after setup)

```bash
# Insecure Flask app (port 5000)
cd flask_website/insecure_flask_app
../.venv/bin/python app.py

# Secure Flask app (port 5001)
cd ../secure_flask_app
export SECURE_FLASK_SECRET="change-me-to-a-long-random-value"
../.venv/bin/python app.py
```

Then visit:

- Insecure app: `http://127.0.0.1:5000/`
- Secure app: `http://127.0.0.1:5001/`

Each app will create its own SQLite database file on first use.

---

### Running with Docker

From the repository root (`~/College/Scripting`):

```bash
# Build and run the insecure Flask app
docker build -f flask_website/insecure_flask_app/Dockerfile -t insecure_flask_app .
docker run -p 5000:5000 insecure_flask_app

# Build and run the secure Flask app
docker build -f flask_website/secure_flask_app/Dockerfile -t secure_flask_app .
docker run -e SECURE_FLASK_SECRET="change-me-to-a-long-random-value" -p 5001:5001 secure_flask_app
```

These commands mount each Flask app into `/app` inside the container and start
them with `python app.py`.

---

### Security differences (high level)

- **Secrets & config**
 - Insecure app hard-codes `SECRET_KEY` and enables `DEBUG=True`.
 - Secure app loads `SECRET_KEY` from `SECURE_FLASK_SECRET` (or generates a
  random value) and uses hardened cookie settings.

- **Authentication & passwords**
 - Insecure app stores **plaintext passwords** and uses string-interpolated SQL
  in login and registration.
 - Secure app stores **hashed passwords** using
  `werkzeug.security.generate_password_hash` / `check_password_hash`, and uses
  parameterised queries.

- **Transactions & search**
 - Insecure app has no CSRF protection, weak validation, and `/search` is
  deliberately vulnerable to **SQL injection** and **reflected XSS**
  (`{{ tx.message | safe }}`).
 - Secure app validates input, uses a simple CSRF token on all POST forms, and
  implements `/search` with a parameterised `LIKE` query while relying on
  Jinja2 auto-escaping.
'
---


