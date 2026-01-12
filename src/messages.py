from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from .db import get_db

bp = Blueprint('messages', __name__, url_prefix='/')

@bp.route("/dashboard")
@login_required
def dashboard():
    return f"""
    Hello, {current_user.username}! <br>
    <a href='{url_for('messages.messages')}'>View Messages</a> | 
    <a href='{url_for('messages.send_message')}'>Send New Message</a> | 
    <a href='{url_for('auth.logout')}'>Logout</a>
    """

@bp.route("/messages")
@login_required
def messages():
    db = get_db()
    user_messages = db.execute(
        'SELECT m.id, m.subject, m.timestamp, m.is_read, u.username as sender_username '
        'FROM messages m JOIN users u ON m.sender_id = u.id '
        'WHERE m.recipient_id = ? ORDER BY m.timestamp DESC',
        (current_user.id,)
    ).fetchall()
    return render_template("messages/messages.html", messages=user_messages)

@bp.route("/message/<int:message_id>")
@login_required
def view_message(message_id):
    db = get_db()
    message = db.execute(
        'SELECT m.*, u.username as sender_username FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = ? AND m.recipient_id = ?',
        (message_id, current_user.id)
    ).fetchone()
    
    if message is None:
        flash("Message not found or you don't have access.")
        return redirect(url_for('messages.messages'))

    if not message['is_read']:
        db.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (message_id,))
        db.commit()

    return render_template("messages/view_message.html", message=message)

@bp.route("/message/<int:message_id>/delete", methods=['POST'])
@login_required
def delete_message(message_id):
    db = get_db()

    message = db.execute(
        'SELECT id FROM messages WHERE id = ? AND recipient_id = ?', (message_id, current_user.id)
    ).fetchone()
    if message:
        db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        db.commit()
        flash("Message deleted")
    else:
        flash("Could not delete this message")
    return redirect(url_for('messages.messages'))

@bp.route("/send", methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        recipient_username = request.form['recipient']
        subject = request.form['subject']
        body = request.form['body']
        db = get_db()
        recipient = db.execute('SELECT * FROM users WHERE username = ?', (recipient_username,)).fetchone()
        
        if recipient is None:
            flash('User not found.')
            return redirect(url_for('messages.send_message'))
        
        db.execute(
            'INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)',
            (current_user.id, recipient['id'], subject, body)
        )
        db.commit()
        flash('Message sent.')
        return redirect(url_for('messages.dashboard'))
        
    return render_template("messages/send_message.html")