## Secure Programming & Scripting – CA2 Project

This repository contains the **CA2 Secure Programming & Scripting** project:

- **Task 1 – Secure Django Website** (`ca2_secure_website/`): modern banking-style
  Django app with authentication, dashboard, profile, transfers, savings planner
  and a **Secure / Insecure mode toggle**.
- **Task 2 – Security Scripts** (`task2_scripts/`): fuzzing, SAST (Bandit) and
  DAST (OWASP ZAP) tooling aimed at the Django app, producing logs and JSON
  reports.
- **Task 3 – DevOps, CI/CD, Docker & Security Documentation** (`docker/`,
  `.github/workflows/CA2.yaml`, `setup.sh`).

The goal is to showcase a **modern banking-style web application** together with
supporting security tooling and automation, suitable for CA2 submission.


### Quick start (development)

1. Create and activate a virtual environment:
   - `python3 -m venv .venv && source .venv/bin/activate`
2. Install root and Django dependencies:
   - `pip install -r requirements.txt`
   - `pip install -r ca2_secure_website/requirements.txt`
3. Initialise the Django database (first time only):
   - `cd ca2_secure_website`
   - `python manage.py makemigrations app`
   - `python manage.py migrate`
   - `python manage.py seed_demo_data`
4. Run the Django app in **secure mode** using SQLite:
   - `USE_SQLITE=1 SECURE_MODE=secure python manage.py runserver 127.0.0.1:8001`
5. To run in **insecure teaching mode** instead:
   - `USE_SQLITE=1 SECURE_MODE=insecure python manage.py runserver 127.0.0.1:8001`

Default demo logins:

- Superuser/admin dashboard: `admin_james / AdminJames123!`
- Normal users: `james`, `mark`, `george`, `mary`, `sarah` – all with password `UserDemo123!`

### Task 2 – Security tooling (fuzzing, SAST, DAST)

From the **project root** (with the app running on `http://127.0.0.1:8001`):

- **Fuzz testing** (with JSON output of all search queries used):

  ```bash
  python task2_scripts/fuzz_test.py \
    --base-url http://127.0.0.1:8001 \
    --path /search/ \
    --iterations 50 \
    --output-json task2_scripts/report_samples/fuzz_results_manual.json
  ```

- **SAST (Bandit)** – writes JSON reports to `task2_scripts/bandit_report_*.json`:

  ```bash
  cd task2_scripts
  python sast_bandit.py --path ../ca2_secure_website --output-json bandit_report_manual.json
  cd ..
  ```

- **DAST (OWASP ZAP)** – requires a ZAP daemon on `localhost:8080`:

  ```bash
  cd task2_scripts
  python dast_zap.py --target http://127.0.0.1:8001 --zap-host localhost --zap-port 8080
  cd ..
  ```

Sample / trimmed reports can be stored under `task2_scripts/report_samples/` for
inclusion in your CA2 submission.

### Running tests (Task 1 + Task 2 integration)

From `ca2_secure_website`:

- Run all tests (both modes, creates/destroys a fresh test DB automatically):  
  `python manage.py test`
- Run only secure-mode Task 2 integrations (fuzz + Bandit):  
  `TEST_MODE=secure python manage.py test`
- Run only insecure-mode Task 2 integrations:  
  `TEST_MODE=insecure python manage.py test`

Logs and reports:

- Text logs: `logs/fuzz_secure.log`, `logs/fuzz_insecure.log`, `logs/bandit_secure.log`, `logs/bandit_insecure.log`
- JSON logs (created by tests and scripts): under `logs/json_logs/`, e.g.:
  - `logs/json_logs/fuzz_results_secure.json`, `fuzz_results_insecure.json`
  - `logs/json_logs/bandit_report_secure.json`, `bandit_report_insecure.json`

### Docker (Task 3)

To run the Django app and Postgres via Docker:

1. Ensure Docker and Docker Compose are installed.
2. From the repo root:
   - `cd docker`
   - `cp .env.example .env` (then edit secrets)
   - `docker compose up --build`

The GitHub Actions workflow (`.github/workflows/CA2.yaml`) runs all of the
above automatically on each push: it installs dependencies, runs tests in both
secure and insecure modes, runs Bandit, builds the Docker image, and then runs
tests again against the Dockerised application.

