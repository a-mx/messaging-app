from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from flask_login import login_user, logout_user, login_required
from passlib.hash import argon2
from .db import get_db
from .models.user import User
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import re
import time

import base64
import io
import pyotp
import qrcode

ARGON2_PARAMS = {
    "type": "ID",
    "rounds": 4,
    "memory_cost": 65536,
    "parallelism": 4,
    "hash_len": 32,
    "salt_size": 16,
}

BITS = 2048
MAX_IP_ATTEMPTS = 5
IP_LOCKOUT_SECONDS = 300
EXAMPLE_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=4,p=4$O6eU0vo/R4jx3puz9n4PoQ$8dVfA6iA4xl1vl6ulw3R7z60nwRdqIDOk6vnZG7qmiE"
ip_attempts_cache = {}

bp = Blueprint('auth', __name__)

def get_real_ip():
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def hash_password(password_with_pepper: str) -> str:
    return argon2.using(
        type=ARGON2_PARAMS["type"],
        rounds=ARGON2_PARAMS["rounds"],
        memory_cost=ARGON2_PARAMS["memory_cost"],
        parallelism=ARGON2_PARAMS["parallelism"],
        hash_len=ARGON2_PARAMS["hash_len"],
        salt_size=ARGON2_PARAMS["salt_size"],
    ).hash(password_with_pepper)

def verify_password(password_with_pepper: str, stored_hash: str) -> bool:
    try:
        return argon2.verify(password_with_pepper, stored_hash)
    except Exception:
        return False

def get_totp_aes_key() -> bytes:
    key = current_app.config.get("TOTP_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("Missing TOTP_ENCRYPTION_KEY in app config")
    try:
        raw = base64.b64decode(key, validate=True)
    except Exception as e:
        raise RuntimeError("Invalid TOTP_ENCRYPTION_KEY (expected base64).") from e
    if len(raw) not in (16, 24, 32):
        raise RuntimeError("Invalid TOTP_ENCRYPTION_KEY length (expected 16/24/32 bytes after base64 decode).")
    return raw

def encrypt_totp_secret(secret: str) -> str:
    key = get_totp_aes_key()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(secret.encode("utf-8"))
    token = base64.b64encode(nonce + tag + ciphertext).decode("utf-8")
    return token

def decrypt_totp_secret(token: str) -> str:
    raw = base64.b64decode(token.encode("utf-8"))

    nonce = raw[:12]
    tag = raw[12:28]
    ciphertext = raw[28:]

    key = get_totp_aes_key()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    secret = cipher.decrypt_and_verify(ciphertext, tag)
    return secret.decode("utf-8")

def lockout_check(ip_addr: str) -> bool:
    if ip_addr in ip_attempts_cache:
        attempts, first_attempt_time = ip_attempts_cache[ip_addr]
        if attempts >= MAX_IP_ATTEMPTS and time.time() - first_attempt_time < IP_LOCKOUT_SECONDS:
            return True
        if time.time() - first_attempt_time >= IP_LOCKOUT_SECONDS:
            ip_attempts_cache.pop(ip_addr, None)
    return False

def record_failed_attempt(ip_addr: str) -> None:
    if ip_addr in ip_attempts_cache:
        attempts, first_attempt_time = ip_attempts_cache[ip_addr]
        ip_attempts_cache[ip_addr] = (attempts + 1, first_attempt_time)
    else:
        ip_attempts_cache[ip_addr] = (1, time.time())

@bp.route("/", methods=['GET', 'POST'])
def login():
    ip_addr = get_real_ip()

    if lockout_check(ip_addr):
        flash("Too many login attempts. Please try again in a few minutes.")
        return render_template("auth/login.html")

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        pepper = current_app.config['PASSWORD_PEPPER']
        password = password + pepper

        stored_hash = user_row['password'] if user_row else EXAMPLE_PASSWORD_HASH
        password_ok = verify_password(password, stored_hash)
        auth_ok = bool(user_row) and password_ok


        if auth_ok:
            ip_attempts_cache.pop(ip_addr, None)
            session.clear()
            session['pre_2fa_user_id'] = user_row['id']
            return redirect(url_for('auth.totp'))
        else:
            record_failed_attempt(ip_addr)
            flash('Wrong username or password.')

    return render_template("auth/login.html")

@bp.route("/totp", methods=["GET", "POST"])
def totp():
    ip_addr = get_real_ip()

    if lockout_check(ip_addr):
        flash("Too many attempts. Please try again in a few minutes.")
        return render_template("auth/totp.html")

    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for("auth.login"))

    db = get_db()
    user_row = db.execute("SELECT id, username, totp_secret FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row or not user_row["totp_secret"]:
        session.pop('pre_2fa_user_id', None)
        flash("2FA is not configured for this account.")
        return redirect(url_for("auth.login"))

    try:
        totp_secret = decrypt_totp_secret(user_row["totp_secret"])
    except Exception:
        session.pop('pre_2fa_user_id', None)
        flash("2FA configuration error.")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if not code.isdigit() or len(code) not in (6, 8):
            record_failed_attempt(ip_addr)
            flash("Invalid code format.")
            return render_template("auth/totp.html")

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(code, valid_window=1):
            ip_attempts_cache.pop(ip_addr, None)
            session.pop('pre_2fa_user_id', None)

            user = User(user_id=user_row['id'], username=user_row['username'])
            login_user(user)
            return redirect(url_for('messages.dashboard'))

        record_failed_attempt(ip_addr)
        flash("Wrong TOTP code.")

    return render_template("auth/totp.html")

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase letters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase letters."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain digits."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain special characters."
    return True, ""

@bp.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message)
            return redirect(url_for('auth.register'))

        db = get_db()
        user_exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if user_exists:
            flash('Username already taken.')
            return redirect(url_for('auth.register'))

        pepper = current_app.config['PASSWORD_PEPPER']
        password_with_pepper = password + pepper
        hashed_password = hash_password(password_with_pepper)

        rsa_keys = RSA.generate(BITS)
        public_key = rsa_keys.public_key().export_key()
        private_key = rsa_keys.export_key(
            passphrase=password,
            pkcs=8,
            protection="scryptAndAES256-CBC"
        )

        totp_secret_plain = pyotp.random_base32()
        totp_secret_enc = encrypt_totp_secret(totp_secret_plain)

        db.execute(
            'INSERT INTO users (username, password, public_key, private_key, totp_secret) VALUES (?, ?, ?, ?, ?)',
            (username, hashed_password, public_key, private_key, totp_secret_enc)
        )
        db.commit()

        session['show_totp_user'] = username
        flash('Registration successful. Set up your authenticator app now.')
        return redirect(url_for("auth.totp_setup"))

    return render_template("auth/register.html")

@bp.route("/totp-setup", methods=["GET"])
def totp_setup():
    username = session.get('show_totp_user')
    if not username:
        return redirect(url_for("auth.login"))

    db = get_db()
    user_row = db.execute("SELECT username, totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    if not user_row:
        session.pop('show_totp_user', None)
        return redirect(url_for("auth.login"))

    try:
        totp_secret = decrypt_totp_secret(user_row["totp_secret"])
    except Exception:
        session.pop('show_totp_user', None)
        flash("2FA configuration error. Contact support.")
        return redirect(url_for("auth.login"))

    issuer = current_app.config.get("TOTP_ISSUER", "ODWSI")
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=user_row["username"], issuer_name=issuer)

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    session.pop('show_totp_user', None)

    return render_template(
        "auth/totp_setup.html",
        qr_b64=qr_b64,
        secret=totp_secret,
        issuer=issuer,
        username=user_row["username"]
    )

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))