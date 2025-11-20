## Docker & Deployment – Task 3

This folder contains Docker resources for running the **CA2 Django banking app**
with a PostgreSQL database.

- `Dockerfile` – builds a production-style image running Django via `gunicorn`.
- `docker-compose.yml` – starts the web container and a Postgres database.
- `.env.example` – example environment file (copy to `.env` and edit values).

### Building and running with Docker Compose

From the repository root:

```bash
cd docker
cp .env.example .env  # then edit secrets and configuration
docker compose up --build
```

This will:

- Start a `db` service (Postgres) with credentials from `.env`.
- Build and run the `web` service using the Django project in `ca2_secure_website`.

The Django app will be available on `http://localhost:8000/` by default.

### Security considerations

- Never commit real secrets or production passwords to `.env` or any other file.
- In production, use:
  - Strong, randomly-generated `DJANGO_SECRET_KEY`.
  - `SECURE_MODE=secure` with HTTPS termination in front of the container.
  - Database credentials managed via a secrets manager or orchestrator (e.g. Kubernetes).


