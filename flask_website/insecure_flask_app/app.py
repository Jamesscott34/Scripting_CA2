import datetime
import os
import sqlite3
import subprocess
import pickle
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


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "insecure.db")


def create_app() -> Flask:
  """
  Create and configure the insecure Flask application.

  This app is intentionally misconfigured for teaching purposes:
  - Hard-coded secret key
  - Debug mode enabled
  - Weak password storage
  - SQL injection and XSS-friendly patterns in some routes
  """

  app = Flask(__name__, template_folder="templates", static_folder="static")

  # VULNERABLE: hard-coded secret key and debug enabled in "production".
  app.config["SECRET_KEY"] = "insecure-demo-secret-key"
  app.config["DEBUG"] = True
  # VULNERABLE: weaken session cookie security flags so that ZAP and other
  # tools can easily detect missing HttpOnly/Secure/SameSite protections.
  app.config["SESSION_COOKIE_HTTPONLY"] = False
  app.config["SESSION_COOKIE_SECURE"] = False
  app.config["SESSION_COOKIE_SAMESITE"] = None

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
      "SELECT id, username, email, balance FROM users WHERE id = ?", (user_id,)
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
    User registration view (intentionally weak).

    VULNERABLE:
    - Passwords stored in plaintext.
    - No input validation on username/password/email.
    - SQL constructed via string interpolation.
    """

    db = g.db # type: ignore[attr-defined]
    if request.method == "POST":
      username = request.form.get("username", "")
      password = request.form.get("password", "")
      email = request.form.get("email", "")

      if not username or not password:
        flash("Username and password are required.", "danger")
        return render_template("register.html")

      # VULNERABLE: SQL injection risk via unescaped user input.
      try:
        db.execute(
          f"""
          INSERT INTO users (username, password, email, balance)
          VALUES ('{username}', '{password}', '{email}', 1000.0)
          """
        )
        db.commit()
        # VULNERABLE: log credentials in clear text to the server log.
        print(f"[INSECURE] Registered user={username!r} password={password!r}")
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
    Insecure login form.

    VULNERABLE:
    - Passwords compared as plaintext.
    - SQL query built using string concatenation.
    - No account lockout or rate limiting.
    """

    db = g.db # type: ignore[attr-defined]
    if request.method == "POST":
      username = request.form.get("username", "")
      password = request.form.get("password", "")

      # VULNERABLE: SQL injection possible via crafted username.
      sql = (
        "SELECT id, username, password, balance "
        f"FROM users WHERE username = '{username}'"
      )
      cur = db.execute(sql)
      row = cur.fetchone()
      if row and row["password"] == password:
        session["user_id"] = row["id"]
        # VULNERABLE: echo the plaintext password into the logs.
        print(f"[INSECURE] Successful login for user={username!r} password={password!r}")
        flash("Logged in successfully.", "success")
        next_url = request.args.get("next") or url_for("dashboard")
        return redirect(next_url)

      # VULNERABLE: still log attempted credentials even when invalid.
      print(f"[INSECURE] Failed login for user={username!r} password={password!r}")
      flash("Invalid credentials.", "danger")

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
    Simple account/profile page.

    VULNERABLE:
    - No CSRF protection on POST.
    - Minimal validation on amount and message (possible abuse/DoS).
    """

    db = g.db # type: ignore[attr-defined]
    user = get_current_user()
    if not user:
      return redirect(url_for("login"))

    if request.method == "POST":
      amount_raw = request.form.get("amount", "0")
      message = request.form.get("message", "")
      try:
        amount = float(amount_raw)
      except ValueError:
        amount = 0.0

      # Allow negative amounts to simulate transfers/withdrawals.
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
    Transaction search endpoint.

    VULNERABLE:
    - SQL injection through the q parameter.
    - Reflected XSS via unsafe rendering of message fields.
    """

    db = g.db # type: ignore[attr-defined]
    user = get_current_user()
    if not user:
      return redirect(url_for("login"))

    query = request.args.get("q", "")
    results = []
    if query:
      # VULNERABLE: query is directly interpolated into the SQL string.
      sql = (
        "SELECT amount, message, created_at "
        "FROM transactions "
        f"WHERE user_id = {user['id']} "
        f"AND message LIKE '%{query}%' "
        "ORDER BY created_at DESC LIMIT 20"
      )
      cur = db.execute(sql)
      results = cur.fetchall()

    return render_template("search.html", user=user, query=query, results=results)

  @app.route("/ping")
  def ping():
    """
    VULNERABLE: command injection via shell=True and unsanitised input.

    This endpoint is intentionally unsafe so that Bandit and DAST tools can
    demonstrate detection of OS command injection issues.
    """

    target = request.args.get("host", "127.0.0.1")
    cmd = f"ping -c 1 {target}"
    # Dangerous pattern: shell=True with user-controlled input. Using
    # check_output() means that non-zero exit codes will raise an
    # exception, which will surface as 5xx errors when fuzzed.
    subprocess.check_output(cmd, shell=True)
    return f"Pinged {target}"

  @app.route("/debug/load")
  def load_debug():
    """
    VULNERABLE: unsafe deserialisation using pickle.loads on untrusted data.

    Accepts a hex-encoded pickle payload via the 'data' query parameter and
    deserialises it directly, which can lead to arbitrary code execution.
    """

    data = request.args.get("data", "")

    # Basic validation to avoid unhandled exceptions when non-hex or malformed
    # data is supplied. We still keep the core insecure behaviour (pickle on
    # untrusted input) but return a clean 400 instead of a 500 traceback for
    # obviously invalid payloads.
    if not data:
      return "No debug payload supplied", 400

    try:
      raw = bytes.fromhex(data)
      obj = pickle.loads(raw)
    except (ValueError, pickle.UnpicklingError) as exc:
      return f"Invalid debug payload: {exc}", 400

    return str(obj)

  @app.route("/admin/dump_users")
  def dump_users():
    """
    EXTREMELY VULNERABLE: unauthenticated endpoint that dumps all users,
    including their plaintext passwords and e-mail addresses.

    This is intentionally unsafe so that ZAP, fuzzing, and manual testing
    can easily detect sensitive information disclosure and poor password
    handling practices.
    """

    db = g.db # type: ignore[attr-defined]
    cur = db.execute("SELECT id, username, password, email, balance FROM users")
    rows = cur.fetchall()
    lines = ["id,username,password,email,balance"]
    for row in rows:
      lines.append(
        f"{row['id']},{row['username']},{row['password']},{row['email']},{row['balance']}"
      )
    return "\n".join(lines), 200, {"Content-Type": "text/plain; charset=utf-8"}

  # Ensure the database schema exists on each request.
  # NOTE:
  # - init_db() uses CREATE TABLE IF NOT EXISTS, so this is safe and cheap.
  # - This also fixes cases where an old insecure.db file exists without
  #   the expected tables, avoiding "no such table: users" errors.
  @app.before_request
  def _ensure_db():
    init_db()

  return app


if __name__ == "__main__":
  flask_app = create_app()
  # Running with debug=True is intentional here for teaching.
  flask_app.run(host="0.0.0.0", port=5000)

# 
