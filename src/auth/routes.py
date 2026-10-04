import base64
import io
import time

import pyotp
import qrcode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from flask import (
    current_app, flash, redirect, render_template, request,
    session, url_for,
)
from flask_login import login_required, login_user, logout_user
from passlib.hash import argon2

from src.extensions import db
from src.auth import auth_bp
from src.models.user import User
from src.auth.forms import (
    LoginForm, RegisterForm, TOTPForm,
    validate_password_strength, validate_username,
)

ip_attempts_cache: dict[str, tuple[int, float]] = {}



def _cfg(key, default=None):
    return current_app.config.get(key, default)


def get_real_ip() -> str:
    return request.headers.get("X-Real-IP") or request.remote_addr


def hash_password(password_with_pepper: str) -> str:
    return argon2.using(
            time_cost=current_app.config.get("ARGON2_TIME_COST"),
            rounds=current_app.config.get("ARGON2_ROUNDS"),
            memory_cost=current_app.config.get("ARGON2_MEMORY_COST"),
            parallelism=current_app.config.get("ARGON2_PARALLELISM"),
            hash_len=current_app.config.get("ARGON2_HASH_LEN"),
            salt_len=current_app.config.get("ARGON2_SALT_LEN"),
        ).hash(password_with_pepper)


def verify_password(password_with_pepper: str, stored_hash: str) -> bool:
    try:
        return argon2.verify(password_with_pepper, stored_hash)
    except Exception:
        return False


def get_totp_aes_key() -> bytes:
    key = _cfg("TOTP_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("Missing TOTP_ENCRYPTION_KEY in app config")
    try:
        return base64.b64decode(key, validate=True)
    except Exception as e:
        raise RuntimeError("Invalid TOTP_ENCRYPTION_KEY") from e


def encrypt_totp_secret(secret: str) -> str:
    key = get_totp_aes_key()
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(secret.encode("utf-8"))
    return base64.b64encode(nonce + tag + ciphertext).decode("utf-8")


def decrypt_totp_secret(token: str) -> str:
    raw = base64.b64decode(token.encode("utf-8"))
    nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
    cipher = AES.new(get_totp_aes_key(), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def lockout_check(ip_addr: str) -> bool:
    max_attempts = _cfg("MAX_IP_ATTEMPTS", 5)
    lockout_seconds = _cfg("IP_LOCKOUT_SECONDS", 300)
    entry = ip_attempts_cache.get(ip_addr)
    if not entry:
        return False

    attempts, first_attempt_time = entry
    elapsed = time.time() - first_attempt_time

    if attempts >= max_attempts and elapsed < lockout_seconds:
        return True
    if elapsed >= lockout_seconds:
        ip_attempts_cache.pop(ip_addr, None)
    return False


def record_failed_attempt(ip_addr: str) -> None:
    if ip_addr in ip_attempts_cache:
        attempts, first = ip_attempts_cache[ip_addr]
        ip_attempts_cache[ip_addr] = (attempts + 1, first)
    else:
        ip_attempts_cache[ip_addr] = (1, time.time())


@auth_bp.route("/", methods=["GET", "POST"])
def login():
    ip_addr = get_real_ip()

    if lockout_check(ip_addr):
        flash("Too many login attempts. Please try again in a few minutes.")
        return render_template("auth/login.html", form=LoginForm())

    form = LoginForm()
    if form.validate_on_submit():
        username = (form.username.data or "").strip()
        password = form.password.data or ""

        if validate_username(username) or validate_password_strength(password):
            record_failed_attempt(ip_addr)
            flash("Wrong username or password.")
            return render_template("auth/login.html", form=form)

        user = User.query.filter_by(username=username).first()

        pepper = _cfg("PASSWORD_PEPPER", "")
        peppered = password + pepper

        example_hash = _cfg("EXAMPLE_PASSWORD_HASH", "")
        stored_hash = user.password if user else example_hash

        password_ok = verify_password(peppered, stored_hash)
        auth_ok = bool(user) and password_ok

        if auth_ok:
            ip_attempts_cache.pop(ip_addr, None)
            session.clear()
            session["pre_2fa_user_id"] = user.id
            return redirect(url_for("auth.totp"))

        record_failed_attempt(ip_addr)
        flash("Wrong username or password.")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/totp", methods=["GET", "POST"])
def totp():
    ip_addr = get_real_ip()

    if lockout_check(ip_addr):
        flash("Too many attempts. Please try again in a few minutes.")
        return render_template("auth/totp.html", form=TOTPForm())

    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.totp_secret:
        session.pop("pre_2fa_user_id", None)
        flash("2FA is not configured for this account.")
        return redirect(url_for("auth.login"))

    try:
        totp_secret = decrypt_totp_secret(user.totp_secret)
    except Exception:
        session.pop("pre_2fa_user_id", None)
        flash("2FA configuration error.")
        return redirect(url_for("auth.login"))

    form = TOTPForm()

    if request.method == "POST":
        if not form.validate():
            record_failed_attempt(ip_addr)
            flash("Invalid code format.")
            return render_template("auth/totp.html", form=form)

        if pyotp.TOTP(totp_secret).verify(form.code.data, valid_window=1):
            ip_attempts_cache.pop(ip_addr, None)
            session.pop("pre_2fa_user_id", None)
            login_user(user)
            return redirect(url_for("messages.dashboard"))

        record_failed_attempt(ip_addr)
        flash("Wrong TOTP code.")

    return render_template("auth/totp.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = (form.username.data or "").strip()
        password = form.password.data or ""

        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return redirect(url_for("auth.register"))

        pepper = _cfg("PASSWORD_PEPPER", "")
        hashed_password = hash_password(password + pepper)

        bits = _cfg("BITS", 2048)
        rsa_keys = RSA.generate(bits)
        public_key = rsa_keys.public_key().export_key().decode("utf-8")
        private_key = rsa_keys.export_key(
            passphrase=password,
            pkcs=8,
            protection="scryptAndAES256-CBC",
        ).decode("utf-8")

        totp_secret_plain = pyotp.random_base32()
        totp_secret_enc = encrypt_totp_secret(totp_secret_plain)

        user = User(
            username=username,
            password=hashed_password,
            public_key=public_key,
            private_key=private_key,
            totp_secret=totp_secret_enc,
        )
        db.session.add(user)
        db.session.commit()

        session["show_totp_user"] = username
        flash("Registration successful.")
        return redirect(url_for("auth.totp_setup"))

    if request.method == "POST":
        for field, errs in form.errors.items():
            for err in errs:
                flash(err)

    return render_template("auth/register.html", form=form)


@auth_bp.route("/totp-setup", methods=["GET"])
def totp_setup():
    username = session.get("show_totp_user")
    if not username:
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(username=username).first()
    if not user:
        session.pop("show_totp_user", None)
        return redirect(url_for("auth.login"))

    try:
        totp_secret = decrypt_totp_secret(user.totp_secret)
    except Exception:
        session.pop("show_totp_user", None)
        flash("2FA configuration error. Contact support.")
        return redirect(url_for("auth.login"))

    issuer = _cfg("TOTP_ISSUER", "Messages")
    uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name=user.username, issuer_name=issuer
    )

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    session.pop("show_totp_user", None)

    return render_template(
        "auth/totp_setup.html",
        qr_b64=qr_b64,
        secret=totp_secret,
        issuer=issuer,
        username=user.username,
    )


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))