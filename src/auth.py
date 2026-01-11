from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from passlib.hash import argon2
from .db import get_db
from .models.user import User

bp = Blueprint('auth', __name__)

@bp.route("/", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user_row and argon2.verify(password, user_row['password']):
            user = User(user_id=user_row['id'], username=user_row['username'])
            login_user(user)
            return redirect(url_for('messages.dashboard'))
        else:
            flash('Wrong username or password.')
    return render_template("auth/login.html")

@bp.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user_exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

        if user_exists:
            flash('Username already taken.')
            return redirect(url_for('auth.register'))

        hashed_password = argon2.hash(password)
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        flash('Registration successful.')
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html")

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))