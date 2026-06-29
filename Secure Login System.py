
import io
import base64
import sqlite3
import bcrypt
import pyotp
import qrcode
from flask import Flask, request, session, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "change-this-in-production"

# ── Database setup ─────────────────────────────────────────────
def get_db():
    db = sqlite3.connect("users.db")
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret   TEXT,
            totp_enabled  INTEGER DEFAULT 0
        )
    """)
    db.commit()
    db.close()

def page(title, body):
    msg = ""
    for cat, text in get_flashed_messages():
        color = "#c0392b" if cat == "error" else "#27ae60"
        msg += f'<p style="color:{color}">{text}</p>'
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 60px auto; padding: 0 20px; }}
  input {{ display:block; width:100%; padding:8px; margin:8px 0 16px; border:1px solid #ccc; border-radius:4px; box-sizing:border-box; }}
  button {{ background:#4f46e5; color:#fff; border:none; padding:10px 20px; border-radius:4px; cursor:pointer; width:100%; }}
  a {{ color:#4f46e5; }}
  h2 {{ margin-bottom:8px; }}
</style></head>
<body>{msg}{body}</body></html>"""


def get_flashed_messages():
    msgs = session.pop("_flashes", [])
    return msgs

def flash(msg, cat="info"):
    session.setdefault("_flashes", []).append((cat, msg))

# ── Routes ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect("/dashboard" if "user" in session else "/login")


# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        # Basic validation
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            try:
                db = get_db()
                # Parameterised query — safe from SQL injection
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                           (username, pw_hash.decode()))
                db.commit()
                db.close()
                flash("Account created! Please log in.", "ok")
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Username already taken.", "error")

    return page("Register", """
        <h2>Create Account</h2>
        <form method="POST">
            <label>Username</label>
            <input name="username" required>
            <label>Password (min 8 chars)</label>
            <input name="password" type="password" required>
            <button>Register</button>
        </form>
        <p><a href="/login">Already have an account?</a></p>
    """)


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            if user["totp_enabled"]:
                session["pending_user"] = username
                return redirect("/verify-2fa")
            session["user"] = username
            flash("Welcome back!", "ok")
            return redirect("/dashboard")
        flash("Wrong username or password.", "error")

    return page("Login", """
        <h2>Login</h2>
        <form method="POST">
            <label>Username</label>
            <input name="username" required>
            <label>Password</label>
            <input name="password" type="password" required>
            <button>Log In</button>
        </form>
        <p><a href="/register">No account yet?</a></p>
    """)


# 2FA verify
@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_user")
    if not username:
        return redirect("/login")

    if request.method == "POST":
        token = request.form["token"].strip()
        db    = get_db()
        user  = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        if pyotp.TOTP(user["totp_secret"]).verify(token, valid_window=1):
            session.pop("pending_user")
            session["user"] = username
            flash("Logged in!", "ok")
            return redirect("/dashboard")
        flash("Invalid code.", "error")

    return page("2FA", """
        <h2>Two-Factor Auth</h2>
        <form method="POST">
            <label>6-digit code from your app</label>
            <input name="token" maxlength="6" inputmode="numeric" required>
            <button>Verify</button>
        </form>
    """)


# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()

    twofa = "✅ Enabled" if user["totp_enabled"] else "❌ Disabled"
    twofa_link = (
        '<form method="POST" action="/disable-2fa"><button style="background:#c0392b">Disable 2FA</button></form>'
        if user["totp_enabled"]
        else '<a href="/setup-2fa"><button>Enable 2FA</button></a>'
    )

    return page("Dashboard", f"""
        <h2>Hello, {username}!</h2>
        <p>Password: 🔒 bcrypt hashed</p>
        <p>2FA: {twofa}</p>
        <br>{twofa_link}<br><br>
        <a href="/logout">Logout</a>
    """)


# Setup 2FA
@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]

    if request.method == "POST":
        token  = request.form["token"].strip()
        secret = session.get("temp_secret")
        if pyotp.TOTP(secret).verify(token, valid_window=1):
            db = get_db()
            db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username=?",
                       (secret, username))
            db.commit()
            db.close()
            session.pop("temp_secret", None)
            flash("2FA enabled!", "ok")
            return redirect("/dashboard")
        flash("Wrong code, try again.", "error")

    # Generate QR code
    secret = pyotp.random_base32()
    session["temp_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SimpleLogin")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    qr = base64.b64encode(buf.getvalue()).decode()

    return page("Setup 2FA", f"""
        <h2>Enable 2FA</h2>
        <p>Scan with Google Authenticator or Authy:</p>
        <img src="data:image/png;base64,{qr}" width="200"><br><br>
        <form method="POST">
            <label>Enter code to confirm</label>
            <input name="token" maxlength="6" inputmode="numeric" required>
            <button>Activate</button>
        </form>
        <p><a href="/dashboard">Cancel</a></p>
    """)


# Disable 2FA
@app.route("/disable-2fa", methods=["POST"])
def disable_2fa():
    if "user" not in session:
        return redirect("/login")
    db = get_db()
    db.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE username=?",
               (session["user"],))
    db.commit()
    db.close()
    flash("2FA disabled.", "ok")
    return redirect("/dashboard")


# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect("/login")


# ── Run ────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
