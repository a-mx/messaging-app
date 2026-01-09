from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
from passlib.hash import argon2

app = Flask(__name__)
app.config['SECRET_KEY'] = '92f46bb69a19c237a1014b94b7a628f0'

login_manager = LoginManager()
login_manager.init_app(app)
DATABASE = "sqlite3.db"
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def user_loader(user_id):
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    sql = db.cursor()
    sql.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_row = sql.fetchone()
    db.close()
    if user_row:
        return User(user_id=user_row['id'], username=user_row['username'])
    return None

@app.route("/", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        sql = db.cursor()
        sql.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_row = sql.fetchone()
        db.close()

        if user_row and argon2.verify(password, user_row['password']):
            user = User(user_id=user_row['id'], username=user_row['username'])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login'))
    return render_template("login.html")
    
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        sql = db.cursor()
        user_exists = sql.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

        if user_exists:
            db.close()
            return redirect(url_for('register'))

        hashed_password = argon2.hash(password)
        sql.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        db.close()
        return redirect(url_for("login"))

    return render_template("register.html")
    
@app.route("/dashboard")
@login_required
def dashboard():
    return f"Hello, {current_user.username}! <a href='{url_for('logout')}'>Logout</a>"
    
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)