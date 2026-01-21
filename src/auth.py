from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from passlib.hash import argon2
from .db import get_db
from .models.user import User
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import re
BITS = 1024
bp = Blueprint('auth', __name__)

@bp.route("/", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        pepper = current_app.config['PASSWORD_PEPPER']

        password = password + pepper


        if user_row and argon2.verify(password, user_row['password']):
            user = User(user_id=user_row['id'], username=user_row['username'])
            login_user(user)
            return redirect(url_for('messages.dashboard'))
        else:
            flash('Wrong username or password.')
    return render_template("auth/login.html")

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
        hashed_password = argon2.hash(password_with_pepper)

        rsa_keys = RSA.generate(BITS)
        public_key = rsa_keys.public_key().export_key()
    
        private_key = rsa_keys.export_key(
            passphrase=password,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )
        

        db.execute('INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)', (username, hashed_password, public_key, private_key))
        db.commit()
        flash('Registration successful.')
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html")

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))