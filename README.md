## Secure Programming & Scripting – CA2 Project

This repository contains the **CA2 Secure Programming & Scripting** project.
It is organised into three main components:

- **Task 1 – Secure Django Website** (`ca2_secure_website/`)
- **Task 2 – Security Scripts** (`task2_scripts/`)
- **Task 3 – DevOps, CI/CD, Docker & Security Documentation** (`docker/`, `CA2.yaml`, `setup.sh`)

The goal is to showcase a **modern banking-style web application** with a
**Secure / Insecure mode toggle**, plus supporting security tooling and automation.

See the individual `README.md` files and `CA2.yaml` for more detailed guidance.


### Quick start (development)

1. Create and activate a virtual environment:
   - `python3 -m venv .venv && source .venv/bin/activate`
2. Install dependencies:
   - `pip install -r ca2_secure_website/requirements.txt`
3. Apply database migrations and run the Django app:
   - `cd ca2_secure_website`
   - `python manage.py migrate`
   - `SECURE_MODE=secure python manage.py runserver`

### Running security tooling (Task 2)

- **Fuzz testing**: `python task2_scripts/fuzz_test.py --base-url http://localhost:8000 --path /search/`
- **SAST (Bandit)**: `cd task2_scripts && python sast_bandit.py`
- **DAST (OWASP ZAP)**: start a ZAP daemon, then run `cd task2_scripts && python dast_zap.py`

Sample reports can be stored under `task2_scripts/report_samples/`.

### Docker (Task 3)

To run the Django app and Postgres via Docker:

1. Ensure Docker and Docker Compose are installed.
2. From the repo root:
   - `cd docker`
   - `cp .env.example .env` (then edit secrets)
   - `docker compose up --build`


