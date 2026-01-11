from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
from passlib.hash import argon2
from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = '92f46bb69a19c237a1014b94b7a628f0'

login_manager = LoginManager()
login_manager.init_app(app)
DATABASE = "sqlite3.db"
login_manager.login_view = 'login'

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
            flash('Wrong username or password.')
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
            flash('Username already taken.')
            return redirect(url_for('register'))

        hashed_password = argon2.hash(password)
        sql.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        db.close()
        flash('Registration successful.')
        return redirect(url_for("login"))

    return render_template("register.html")
    
@app.route("/dashboard")
@login_required
def dashboard():
    # Dodajemy linki do wiadomości na pulpicie
    return f"""
        Hello, {current_user.username}! <br>
        <a href='{url_for('messages')}'>View Messages</a> | 
        <a href='{url_for('send_message')}'>Send New Message</a> | 
        <a href='{url_for('logout')}'>Logout</a>
    """

@app.route("/messages")
@login_required
def messages():
    """Wyświetla skrzynkę odbiorczą użytkownika."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    
    # Pobieramy wiadomości dla zalogowanego użytkownika, łącząc z tabelą users, aby uzyskać nazwę nadawcy
    user_messages = db.execute(
        'SELECT m.id, m.subject, m.timestamp, m.is_read, u.username as sender_username '
        'FROM messages m JOIN users u ON m.sender_id = u.id '
        'WHERE m.recipient_id = ? ORDER BY m.timestamp DESC',
        (current_user.id,)
    ).fetchall()
    
    db.close()
    return render_template("messages.html", messages=user_messages)

@app.route("/message/<int:message_id>")
@login_required
def view_message(message_id):
    """Wyświetla pojedynczą wiadomość i oznacza ją jako przeczytaną."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    
    message = db.execute(
        'SELECT m.*, u.username as sender_username FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ? AND m.recipient_id = ?',
        (message_id, current_user.id)
    ).fetchone()
    
    if message is None:
        flash("Wiadomość nie istnieje lub nie masz do niej dostępu.")
        return redirect(url_for('messages'))

    # Oznacz wiadomość jako przeczytaną
    if not message['is_read']:
        db.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (message_id,))
        db.commit()

    db.close()
    return render_template("view_message.html", message=message)

@app.route("/send", methods=['GET', 'POST'])
@login_required
def send_message():
    """Formularz do wysyłania nowej wiadomości."""
    if request.method == 'POST':
        recipient_username = request.form['recipient']
        subject = request.form['subject']
        body = request.form['body']
        
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        
        recipient = db.execute('SELECT * FROM users WHERE username = ?', (recipient_username,)).fetchone()
        
        if recipient is None:
            flash('Użytkownik o podanej nazwie nie istnieje.')
            return redirect(url_for('send_message'))
        
        db.execute(
            'INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)',
            (current_user.id, recipient['id'], subject, body)
        )
        db.commit()
        db.close()
        
        flash('Wiadomość została wysłana.')
        return redirect(url_for('dashboard'))
        
    return render_template("send_message.html")
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)