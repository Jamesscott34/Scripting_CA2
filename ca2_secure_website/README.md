
## CA2 Secure Django Banking Website

This Django project implements a **banking-style web application** with:

- User registration and login
- Dashboard and profile views
- Simple account/search views
- A **Secure / Insecure mode toggle** controlled via environment variables

The code is structured for teaching **secure coding practices**, showing how
settings and views change under different security modes.
 
### Running the site (development)

From the repository root:

1. Create and activate a virtual environment:
   - `python3 -m venv .venv && source .venv/bin/activate`
2. Install dependencies:
   - `pip install -r requirements.txt`
   - `pip install -r ca2_secure_website/requirements.txt`
3. Initialise the database (first time only):
   - `cd ca2_secure_website`
   - `python manage.py makemigrations app`
   - `python manage.py migrate`
   - `python manage.py seed_demo_data`
4. Run the development server (using SQLite):
   - **Secure mode:** `USE_SQLITE=1 SECURE_MODE=secure python manage.py runserver 127.0.0.1:8001`
   - **Insecure mode:** `USE_SQLITE=1 SECURE_MODE=insecure python manage.py runserver 127.0.0.1:8001`

Default demo accounts:

- Admin / staff: `admin_james / AdminJames123!` → redirected to `/admin-dashboard/`
- Users: `james`, `mark`, `george`, `mary`, `sarah` – password `UserDemo123!`

### Secure / Insecure behaviour

- **Secure mode**
  - Uses ORM-based search.
  - Blocks transfers that would overdraw an account.
  - Sets stricter security headers and cookies.
- **Insecure mode**
  - Uses an intentionally unsafe raw SQL search.
  - Relaxes some security checks for teaching/demonstration.

The active mode is visible in the navbar badge on every page and can also be
toggled from the custom admin dashboard.

