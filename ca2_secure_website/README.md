## CA2 Secure Django Banking Website

This Django project implements a **banking-style web application** with:

- User registration and login
- Dashboard and profile views
- Simple account/search views
- A **Secure / Insecure mode toggle** controlled via environment variables

The code is structured for teaching **secure coding practices**, showing how
settings and views change under different security modes.
 
### Running the site

1. Ensure dependencies are installed (from the repo root):
   - `python3 -m venv .venv && source .venv/bin/activate`
   - `pip install -r ca2_secure_website/requirements.txt`
2. Apply migrations:
   - `python manage.py migrate`
3. Run the development server:
   - `python manage.py runserver`

### Secure / Insecure mode toggle

The security mode is controlled by the `SECURE_MODE` environment variable:

- `SECURE_MODE=secure` (default) – enables hardened settings and ORM-based search.
- `SECURE_MODE=insecure` – disables some protections and uses an intentionally
  unsafe raw SQL example in the search view for demonstration purposes.

The active mode is visible in the navbar badge on every page.

