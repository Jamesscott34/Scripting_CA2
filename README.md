## Secure Programming & Scripting – CA2 Project

[![CA2 CI Status](https://github.com/jamesscott34/Scripting_CA2/actions/workflows/CA2.yaml/badge.svg)](https://github.com/<your-github-username>/Scripting_CA2/actions/workflows/CA2.yaml)

> Replace `<your-github-username>` with your actual GitHub username to enable the badge.

This repository contains the **CA2 Secure Programming & Scripting** project:

- **Task 1 – Secure Django Website** (`ca2_secure_website/`): modern banking-style
  Django app with authentication, dashboard, profile, transfers, savings planner
  and a **Secure / Insecure mode toggle**.
- **Task 2 – Security Scripts** (`task2_scripts/`): fuzzing, SAST (Bandit) and
  DAST (OWASP ZAP) tooling aimed at the Django app, producing logs and JSON
  reports.
- **Task 3 – DevOps, CI/CD, Docker & Security Documentation** (`docker/`,
  `.github/workflows/CA2.yaml`, `setup.sh`).

The goal is to showcase a **web application** together with
supporting security tooling and automation, suitable for CA2 submission.


### One‑command setup

For a full CA2 demo on a fresh machine (virtualenv, migrations, tests, Docker build,
and Docker tests) you can simply run:

```bash
chmod +x setup.sh
./setup.sh
```

This script will:

- **Create and activate** a Python virtual environment in `.venv`.
- **Install all dependencies** from the root `requirements.txt` (Django app + security tools).
- **Run migrations and seed demo data** for the Django app.
- **Run Django tests** in both **secure** and **insecure** modes on SQLite.
- **Build and start** the Docker Compose stack (`web` + `db`) in the `docker/` directory.
- **Run Django tests inside Docker** for both secure and insecure modes.

After `setup.sh` completes:

- The Dockerised app and database are **still running** (see Docker section below).
- You can stop them later with:

  ```bash
  cd docker
  docker compose down -v
  ```


### Quick start (manual development)

1. **Create and activate a virtual environment**:
   - `python3 -m venv .venv && source .venv/bin/activate`
2. **Install project dependencies**:
   - `pip install -r requirements.txt`
3. **Initialise the Django database** (first time only):
   - `cd ca2_secure_website`
   - `python manage.py makemigrations app`
   - `python manage.py migrate`
   - `python manage.py seed_demo_data`
4. **Run the Django app in secure mode** using SQLite:
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

  - **Summary-only mode for quick checks**:

    ```bash
    # Run fuzzing but only print console summaries (status, anomalies, OWASP mapping),
    # without writing JSON/log/Excel artefacts.
    python task2_scripts/fuzz_test.py \
      -t http://127.0.0.1:8001 \
      --auto \
      --summary-only
    ```

    At the end of each run the fuzzer prints:
    - Status code distribution.
    - Anomaly counts (slow responses, 5xx, error signatures, reflection, etc.).
    - Approximate OWASP Top 10 signals (e.g. A03 Injection (XSS), A05 Misconfiguration),
      based on the detected anomaly reasons.
    - Input coverage summary (how many requests used file uploads, custom headers, cookies).

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

  For a quick CA2 run with standardised filenames and a text summary log, you
  can also use the automatic mode from the **project root**:

  ```bash
  python task2_scripts/sast_bandit.py \
    --auto \
    --mode insecure

  python task2_scripts/sast_bandit.py \
    --auto \
    --mode secure
  ```

  In both cases, if you do not override `--mode` it defaults to **insecure**.

  With automatic naming, the files are named based on the target being
  scanned, so running against:

  - `../ca2_secure_website` will produce:
    - JSON: `logs/json_logs/ca2_secure_website_bandit_<ddmmyy>.json`
    - Log: `logs/ca2_secure_website_bandit_<ddmmyy>.log`
    - Excel: `logs/excel/ca2_secure_website_bandit_<ddmmyy>.xlsx`

  For CI-style gating you can also add `--fail-on-high` or `--fail-on-medium`
  to have the command exit non-zero if Bandit reports issues of those
  severities.

  For quick local checks without writing any artefacts you can add
  `--summary-only`, which only prints the Bandit summary (HIGH/MEDIUM/LOW
  counts and lines of code analysed) plus an approximate OWASP Top 10
  classification of findings to the console. This is useful when demonstrating
  SAST behaviour against "any Python code", not just the Django project.

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
      --formats json,html,xml,xlsx
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
      -t http://127.0.0.1:8001 \
      --auto \
      --fail-on-medium
    ```

    `--fail-on-high` and `--fail-on-medium` cause the script to exit with a
    non-zero code if High (or Medium/High) alerts are present, making it easy
    to plug into GitHub Actions or other CI pipelines. In `--auto` mode
    reports are named like `logs/zap_reports/zap_<host>_<ddmmyy>.json|html|md|xlsx`.

  - **Noise reduction and baselines**:

    - Ignore expected alerts via regex, e.g.:

      ```bash
      python task2_scripts/dast_zap.py \
        -t http://127.0.0.1:8001 \
        --auto \
        --ignore-alerts "Login failed" "CSRF token missing"
      ```

    - Compare against a previous JSON report to see trends in severity counts:

      ```bash
      python task2_scripts/dast_zap.py \
        -t http://127.0.0.1:8001 \
        --auto \
        --baseline-json logs/zap_reports/zap_127_0_0_1_8001_010125.json
      ```

      This prints a small "Trend vs baseline" table for High/Medium/Low/Informational alerts.

  - **Summary-only runs**:

    ```bash
    python task2_scripts/dast_zap.py \
      -t http://127.0.0.1:8001 \
      --auto \
      --summary-only
    ```

    This prints a concise ZAP severity table, an approximate OWASP Top 10
    summary based on alert names, and a few sample alerts without writing
    JSON/HTML/Excel artefacts, useful for fast local smoke checks.

  - **Optional SARIF output (for GitHub Security dashboards)**:

    ```bash
    python task2_scripts/dast_zap.py \
      -t http://127.0.0.1:8001 \
      --auto \
      --sarif-path logs/zap_reports/zap_ca2.sarif
    ```

    This generates a minimal SARIF report mapping each ZAP alert to a SARIF
    rule/result pair, suitable for upload to GitHub Code Scanning.

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

- Text logs from Task 2 integrations and scripts (examples):  
  `logs/fuzz_secure.log`, `logs/fuzz_insecure.log`, `logs/bandit_secure.log`, `logs/bandit_insecure.log`
- JSON logs (created by tests and scripts) under `logs/json_logs/`, e.g.:
  - `logs/json_logs/fuzz_results_secure.json`, `fuzz_results_insecure.json`
  - `logs/json_logs/bandit_report_secure.json`, `bandit_report_insecure.json`


### Docker (Task 3 – Docker & Docker Compose)

To run the Django app and PostgreSQL via Docker:

1. Ensure **Docker** and **Docker Compose v2** are installed.
2. From the repo root:
   - `cd docker`
   - Optionally create a `.env` file to override defaults (database password, etc.).
   - Start the stack:

     ```bash
     docker compose up --build
     ```

This will:

- Build the multi-stage Docker image defined in `docker/Dockerfile` using the
  `SECURE_MODE` build argument.
- Start:
  - `web`: Django app running as a non-root user with `dumb-init`, health checks,
    and `psycopg2-binary` for PostgreSQL.
  - `db`: PostgreSQL database with a simple health check.
- Use the internal hostname `db` (`POSTGRES_HOST=db`) so Django can talk to Postgres.

You can stop and clean up containers and volumes with:

```bash
cd docker
docker compose down -v
```


### CI/CD pipeline, Docker, and OWASP controls (Task 3)

The GitHub Actions workflow (`.github/workflows/CA2.yaml`) runs on every push to
`main` and on pull requests. It:

- Installs Python and caches pip dependencies.
- Installs project requirements and Bandit (with SARIF support).
- Runs dependency scanners (**pip-audit**, **Safety**).
- Runs Django tests in **secure** and **insecure** modes on SQLite.
- Runs **Bandit SAST** and uploads SARIF to GitHub Code Scanning.
- Builds and runs the **Docker Compose** stack and re-runs Django tests in Docker.
- Scans the Docker image with **Trivy** (HIGH/CRITICAL gating).
- Runs an **OWASP ZAP DAST** scan in `--auto` mode with severity gating.
- Uploads logs and reports as CI artefacts.

High-level pipeline flow:

```mermaid
flowchart LR
    A[Developer Commit] --> B[GitHub Repo]

    B --> C[GitHub Actions CI Pipeline]

    C --> D[Install Dependencies &amp; Security Tools]

    C --> E[Run Django Tests<br/>SECURE + INSECURE Modes]

    C --> F[Static Analysis<br/>(Bandit SAST)]

    D --> G[Build Docker Images]

    E --> G

    G --> H[Run Tests in Docker Containers]

    H --> I{Tests Passing?}

    I -->|No| X[Stop Pipeline<br/>Fail Build]

    I -->|Yes| J[Push Docker Image to Registry<br/>(Optional Enhancement)]

    J --> K[Deploy to Staging<br/>Docker Compose / Kubernetes]

    K --> L[Staging Smoke Tests]

    L -->|Pass| M[Deploy to Production]

    L -->|Fail| R[Rollback to Previous Image]
```

OWASP CI/CD control mapping:

| Pipeline Step in YAML                      | OWASP Control                            | How You Meet It                                                                        |
| ------------------------------------------ | ---------------------------------------- | -------------------------------------------------------------------------------------- |
| Running unit tests & secure/insecure tests | CICD-SEC-01 (Secure Build)               | Ensures application behaves correctly in both secure and intentionally insecure modes. |
| Bandit SAST scan                           | CICD-SEC-08 (Automated Security Testing) | Static analysis integrated into the CI pipeline.                                       |
| Docker image build & container tests       | CICD-SEC-05 (Harden Build Environment)   | Builds occur in clean ephemeral runners.                                               |
| Optional image signing/storage             | CICD-SEC-09 (Artifact Integrity)         | Docker image creation (and potential registry push) creates auditable artifacts.       |
| Dependency scanners (pip-audit, Safety)     | CICD-SEC-07 (Dependency Management)      | Automatically checks Python dependencies for known CVEs on every pipeline run.        |
| Trivy container image scan                  | CICD-SEC-08 (Automated Security Testing) | Scans built Docker images for HIGH/CRITICAL vulnerabilities before they are used.     |
| ZAP DAST scan step                          | CICD-SEC-08 (Automated Security Testing) | Performs authenticated dynamic security testing against the running application.      |
| SARIF upload to GitHub Code Scanning        | CICD-SEC-09 (Artifact Integrity)         | Centralises SAST findings in GitHub for tracking, triage, and historical comparison.  |
| Logs & reports uploaded as CI artifacts     | CICD-SEC-09 (Artifact Integrity)         | Persists test and security reports for audit trails and post-run analysis.            |
