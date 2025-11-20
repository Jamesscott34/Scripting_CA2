## Task 2 – Standalone Security Scripts

This folder contains **standalone Python scripts** used to analyse and test the
CA2 Django banking application.

- `fuzz_test.py` – sends randomised HTTP requests to a chosen endpoint
  (defaults to `/search/`) to explore how the app behaves under unexpected
  input.
- `sast_bandit.py` – runs **Bandit** (static application security testing)
  recursively against the Django project and writes a JSON report.
- `dast_zap.py` – orchestrates a basic **OWASP ZAP** dynamic scan against a
  running instance of the Django application.

### Example usage

From the project root, with the Django app running locally on port 8000:

```bash
source .venv/bin/activate

# Fuzz the search endpoint
python task2_scripts/fuzz_test.py --base-url http://localhost:8000 --path /search/ --iterations 50

# Run Bandit SAST and produce a JSON report
cd task2_scripts
python sast_bandit.py --path ../ca2_secure_website --output-json bandit_report.json

# Run OWASP ZAP DAST (requires a ZAP daemon listening on localhost:8080)
python dast_zap.py --target http://localhost:8000 --zap-host localhost --zap-port 8080
```

Sample / trimmed reports can be stored under `report_samples/` for inclusion in
your CA2 submission.


