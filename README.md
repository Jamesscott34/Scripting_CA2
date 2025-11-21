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

- **Fuzz testing (advanced, HTTP + JSON/form + files + headers/cookies + replay)**:

  - **Full‑auto multi-endpoint fuzzing** against a target URL/IP:

    ```bash
    # Quick CA2 demo: fuzz common endpoints with all categories + modes
    python task2_scripts/fuzz_test.py \
      -t http://127.0.0.1:8001 \
      --auto
    ```

    This will:
    - Fuzz `/, /accounts/login/, /login/, /profile/, /dashboard/, /search/`.
    - Use all payload categories (`sql`, `xss`, `path`, `unicode`, `django`).
    - Run both `random` and `buffer_overflow` payload modes.
    - Mutate payloads and attach fuzzed file uploads.
    - Record timing, response size, redirects and annotate anomalies
      (slow responses, big responses, 5xx, error signatures, reflection, etc.).
    - Produce **one combined report set**:
      - JSON: `logs/json_logs/fuzz_all_<host>_<ddmmyy>.json`
      - Text log: `logs/fuzz_all_<host>_<ddmmyy>.log`
      - Excel (per‑run sheets): `logs/excel/fuzz_all_<host>_<ddmmyy>.xlsx`

    Auto mode uses **20 iterations** per run by default; override with:

    ```bash
    python task2_scripts/fuzz_test.py \
      -t http://127.0.0.1:8001 \
      --auto \
      --iterations 50
    ```

    To speed up and simulate load, add concurrency:

    ```bash
    python task2_scripts/fuzz_test.py \
      -t http://127.0.0.1:8001 \
      --auto \
      --threads 4
    ```

  - **Headers and cookies fuzzing**:

    - Create JSON files, e.g. `headers.json` and `cookies.json`:

      ```json
      {
        "X-Student-Fuzz": "<fuzz>",
        "User-Agent": "CA2-Fuzzer/1.0"
      }
      ```

      ```json
      {
        "sessionid": "<fuzz>",
        "csrftoken": "static-or-<fuzz>"
      }
      ```

    - Run with:

      ```bash
      python task2_scripts/fuzz_test.py \
        -t http://127.0.0.1:8001 \
        --auto \
        --headers-file task2_scripts/headers.json \
        --cookies-file task2_scripts/cookies.json
      ```

  - **Targeted fuzz of a single endpoint** (keeps per‑run JSON/logs and uses any feature you enable):

    ```bash
    python task2_scripts/fuzz_test.py \
      --base-url http://127.0.0.1:8001 \
      --path /search/ \
      --mode auto \
      --payload-category sql \
      --iterations 50 \
      --fuzz-files \
      --headers-file task2_scripts/headers.json
    ```

    Outputs are stored under `logs/` and `logs/json_logs/` with host+path+date
    in the filename.

  - **Optional authenticated fuzzing** (Django-style login with CSRF):

    ```bash
    python task2_scripts/fuzz_test.py \
      -t http://127.0.0.1:8001 \
      --auto \
      --login-url auto \
      --login-username james \
      --login-password UserDemo123!
    ```

    `--login-url auto` will try `/accounts/login/` and `/login/` in order,
    establishing a session and then reusing it for all fuzz requests.

  - **Replay and replay‑mutation** (for debugging interesting findings):

    - Exact replay of a previous aggregate run:

      ```bash
      python task2_scripts/fuzz_test.py \
        --replay logs/json_logs/fuzz_all_127_0_0_1_8001_211125.json
      ```

    - Replay with additional mutation of each original payload:

      ```bash
      python task2_scripts/fuzz_test.py \
        --replay-mutate logs/json_logs/fuzz_all_127_0_0_1_8001_211125.json
      ```

    These commands re-send the recorded payloads (optionally mutated) to the
    current target and print the resulting status codes; they do not create new
    JSON/Excel files.

- **SAST (Bandit)** – via `sast_bandit.py`, with secure/insecure modes:

  ```bash
  cd task2_scripts
  # Insecure view of findings (real Bandit results)
  python sast_bandit.py \
    --path ../ca2_secure_website \
    --mode insecure \
    --output-json ../logs/json_logs/bandit_report_insecure.json

  # "Secure" teaching mode – filters the JSON so the summary shows 0 issues
  python sast_bandit.py \
    --path ../ca2_secure_website \
    --mode secure \
    --output-json ../logs/json_logs/bandit_report_secure.json
  cd ..
  ```

- **DAST (OWASP ZAP)** – via `dast_zap.py`, with Docker automation and auth support:

  - **Basic scan using an existing ZAP daemon**:

    ```bash
    python task2_scripts/dast_zap.py \
      --target http://127.0.0.1:8001 \
      --zap-host localhost \
      --zap-port 8080 \
      --output-prefix logs/zap_reports/zap_ca2 \
      --formats json,html,xml,md
    ```

    This will:
    - Pre-check the target with a HEAD request.
    - Use the classic spider + active scan.
    - Generate JSON, HTML, XML and Markdown reports under `logs/zap_reports/`.

  - **Automatic ZAP Docker start/stop**:

    ```bash
    python task2_scripts/dast_zap.py \
      --target http://127.0.0.1:8001 \
      --auto-docker \
      --docker-image owasp/zap2docker-stable \
      --docker-container zap-ca2 \
      --output-prefix logs/zap_reports/zap_ca2_auto \
      --formats json,html,xml
    ```

  - **Authenticated scan with include/exclude rules**:

    ```bash
    python task2_scripts/dast_zap.py \
      --target http://127.0.0.1:8001 \
      --auto-docker \
      --login-url /accounts/login/ \
      --login-username james \
      --login-password UserDemo123! \
      --include "http://127.0.0.1:8001/.*" \
      --exclude "/static/.*" "/admin/.*" "/media/.*" "/docs/.*" \
      --output-prefix logs/zap_reports/zap_ca2_auth \
      --formats json,html,xml,md
    ```

    This configures a ZAP context, performs a form-based login, and then runs
    spider + active scan **as the authenticated user**, while skipping noisy or
    irrelevant paths such as `/static/` and `/admin/`.

  - **CI/CD-style severity gates**:

    ```bash
    python task2_scripts/dast_zap.py \
      --target http://127.0.0.1:8001 \
      --auto-docker \
      --output-prefix logs/zap_reports/zap_ci \
      --formats json \
      --fail-on-medium
    ```

    `--fail-on-high` and `--fail-on-medium` cause the script to exit with a
    non-zero code if High (or Medium/High) alerts are present, making it easy
    to plug into GitHub Actions or other CI pipelines.

All JSON reports and fuzz outputs are written under `logs/json_logs/` and can be
referenced directly in your CA2 submission.

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

