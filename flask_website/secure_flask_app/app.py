import datetime
import os
import re
import secrets
import sqlite3
from functools import wraps

from flask import (
  Flask,
  g,
  redirect,
  render_template,
  request,
  session,
  url_for,
  flash,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secure.db")


def create_app() -> Flask:
  """
  Create and configure the secure Flask application.

  This app mirrors the insecure Flask demo but applies security best
  practices: hashed passwords, parameterised SQL, CSRF protection, safer
  session handling and access control.
  """

  app = Flask(__name__, template_folder="templates", static_folder="static")

  # Load a strong secret key from the environment, falling back to a random
  # value for local development. In real deployments, SECURE_FLASK_SECRET
  # should always be set.
  app.config["SECRET_KEY"] = os.environ.get(
    "SECURE_FLASK_SECRET", secrets.token_hex(32)
  )
  app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"

  # Hardened cookie settings.
  app.config["SESSION_COOKIE_HTTPONLY"] = True
  app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
  app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("FLASK_SECURE_COOKIES", "0") == "1"
  )

  @app.before_request
  def _open_db() -> None:
    if "db" not in g:
      conn = sqlite3.connect(DB_PATH)
      conn.row_factory = sqlite3.Row
      g.db = conn

  @app.teardown_appcontext
  def _close_db(exc) -> None: # type: ignore[override]
    db = g.pop("db", None)
    if db is not None:
      db.close()

  def init_db() -> None:
    """Initialise the SQLite schema if it does not already exist."""

    db = g.db # type: ignore[attr-defined]
    db.executescript(
      """
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        balance REAL NOT NULL DEFAULT 1000.0
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
      );
      """
    )
    db.commit()

  def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
      return None
    db = g.db # type: ignore[attr-defined]
    cur = db.execute(
      "SELECT id, username, email, balance FROM users WHERE id = ?",
      (user_id,),
    )
    return cur.fetchone()

  def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
      if not session.get("user_id"):
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login", next=request.path))
      return fn(*args, **kwargs)

    return wrapper

  # --- CSRF protection helpers -------------------------------------------------

  def _get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
      token = secrets.token_hex(16)
      session["csrf_token"] = token
    return token

  @app.before_request
  def _csrf_protect() -> None:
    # Only enforce CSRF on modifying requests.
    if request.method in {"POST", "PUT", "DELETE", "PATCH"}:
      session_token = session.get("csrf_token")
      form_token = request.form.get("csrf_token")
      if not session_token or not form_token or session_token != form_token:
        flash("Security check failed. Please try again.", "danger")
        return redirect(url_for("login"))

  app.jinja_env.globals["csrf_token"] = _get_csrf_token

  # --- Simple validation helpers ----------------------------------------------

  _USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")

  def validate_credentials(username: str, password: str) -> bool:
    if not _USERNAME_RE.match(username or ""):
      flash(
        "Username must be 3–30 characters of letters, numbers or underscores.",
        "danger",
      )
      return False
    if not password or len(password) < 8:
      flash("Password must be at least 8 characters long.", "danger")
      return False
    return True

  # --- Routes ------------------------------------------------------------------

  @app.route("/")
  def dashboard():
    """Landing page / dashboard similar to the Django dashboard view."""

    db = g.db # type: ignore[attr-defined]
    user = get_current_user()
    txs = []
    if user:
      cur = db.execute(
        "SELECT amount, message, created_at "
        "FROM transactions WHERE user_id = ? "
        "ORDER BY created_at DESC LIMIT 10",
        (user["id"],),
      )
      txs = cur.fetchall()
    return render_template("dashboard.html", user=user, transactions=txs)

  @app.route("/register", methods=["GET", "POST"])
  def register():
    """
    Secure user registration view.

    - Validates username and password.
    - Stores a salted password hash instead of plaintext.
    - Uses parameterised SQL to avoid injection.
    """

    db = g.db # type: ignore[attr-defined]
    if request.method == "POST":
      username = request.form.get("username", "").strip()
      password = request.form.get("password", "")
      email = request.form.get("email", "").strip()

      if not validate_credentials(username, password):
        return render_template("register.html")

      pw_hash = generate_password_hash(password)
      try:
        db.execute(
          "INSERT INTO users (username, password, email, balance) "
          "VALUES (?, ?, ?, 1000.0)",
          (username, pw_hash, email),
        )
        db.commit()
      except sqlite3.IntegrityError:
        flash("Username already exists.", "danger")
        return render_template("register.html")

      cur = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
      )
      row = cur.fetchone()
      if row:
        session["user_id"] = row["id"]
        flash("Account created. Logged in as new user.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")

  @app.route("/login", methods=["GET", "POST"])
  def login():
    """
    Secure login form.

    - Looks up user via parameterised query.
    - Verifies password using a salted hash.
    - Does not reveal whether the username or password was incorrect.
    """

    db = g.db # type: ignore[attr-defined]
    if request.method == "POST":
      username = request.form.get("username", "").strip()
      password = request.form.get("password", "")

      cur = db.execute(
        "SELECT id, username, password, balance "
        "FROM users WHERE username = ?",
        (username,),
      )
      row = cur.fetchone()
      if row and check_password_hash(row["password"], password):
        session["user_id"] = row["id"]
        flash("Logged in successfully.", "success")
        next_url = request.args.get("next") or url_for("dashboard")
        return redirect(next_url)

      flash("Invalid username or password.", "danger")

    return render_template("login.html")

  @app.route("/logout")
  def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

  @app.route("/profile", methods=["GET", "POST"])
  @login_required
  def profile():
    """
    Secure account/profile page.

    - Requires login.
    - Parameterised updates and inserts.
    - Basic input validation on the transaction amount and message.
    """

    db = g.db # type: ignore[attr-defined]
    user = get_current_user()
    if not user:
      return redirect(url_for("login"))

    if request.method == "POST":
      amount_raw = request.form.get("amount", "0").strip()
      message = request.form.get("message", "").strip()

      try:
        amount = float(amount_raw)
      except ValueError:
        flash("Amount must be a number.", "danger")
        return redirect(url_for("profile"))

      if abs(amount) > 1_000_000:
        flash("Amount is unreasonably large.", "danger")
        return redirect(url_for("profile"))

      if len(message) > 255:
        flash("Message is too long.", "danger")
        return redirect(url_for("profile"))

      new_balance = user["balance"] + amount
      db.execute(
        "UPDATE users SET balance = ? WHERE id = ?",
        (new_balance, user["id"]),
      )
      db.execute(
        "INSERT INTO transactions (user_id, amount, message, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
          user["id"],
          amount,
          message or "Manual adjustment",
          datetime.datetime.utcnow().isoformat(),
        ),
      )
      db.commit()
      flash("Transaction recorded.", "success")
      return redirect(url_for("profile"))

    cur = db.execute(
      "SELECT amount, message, created_at "
      "FROM transactions WHERE user_id = ? "
      "ORDER BY created_at DESC LIMIT 20",
      (user["id"],),
    )
    txs = cur.fetchall()
    return render_template("profile.html", user=user, transactions=txs)

  @app.route("/search")
  @login_required
  def search():
    """
    Transaction search endpoint (secure).

    - Uses parameterised LIKE query to avoid SQL injection.
    - Relies on Jinja2 auto-escaping to prevent XSS.
    """

    db = g.db # type: ignore[attr-defined]
    user = get_current_user()
    if not user:
      return redirect(url_for("login"))

    query = request.args.get("q", "").strip()
    results = []
    if query:
      like_value = f"%{query}%"
      cur = db.execute(
        "SELECT amount, message, created_at "
        "FROM transactions "
        "WHERE user_id = ? AND message LIKE ? "
        "ORDER BY created_at DESC LIMIT 20",
        (user["id"], like_value),
      )
      results = cur.fetchall()

    return render_template("search.html", user=user, query=query, results=results)

  # Ensure the database exists on first request.
  @app.before_request
  def _ensure_db():
    if not os.path.exists(DB_PATH):
      init_db()

  # Basic, non-verbose error handlers.
  @app.errorhandler(404)
  def _not_found(exc): # type: ignore[override]
    return render_template("error.html", message="Page not found."), 404

  @app.errorhandler(500)
  def _server_error(exc): # type: ignore[override]
    return (
      render_template(
        "error.html",
        message="An internal error occurred. Please try again later.",
      ),
      500,
    )

  return app


if __name__ == "__main__":
  flask_app = create_app()
  # Default to port 5001 so it can run alongside the insecure app.
  flask_app.run(host="0.0.0.0", port=5001)

# 
