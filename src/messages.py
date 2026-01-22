from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from .db import get_db
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

bp = Blueprint('messages', __name__, url_prefix='/')

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def _signature_message(encrypted_payload: dict) -> bytes:
    """
    Zwraca bytes do podpisu/weryfikacji.
    Podpisujemy kanonicznie wybrane pola payloadu (base64 stringi),
    żeby uniknąć różnic serializacji JSON.
    """
    parts = [
        encrypted_payload["encrypted_aes_key"],
        encrypted_payload["nonce"],
        encrypted_payload["tag"],
        encrypted_payload["ciphertext"],
    ]
    return ("|".join(parts)).encode("utf-8")

@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("messages/dashboard.html")

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

@bp.route("/message/<int:message_id>", methods=['GET', 'POST'])
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

    if request.method == 'POST':
        password = request.form.get('password')

        try:
            user_private_key_encrypted = db.execute(
                'SELECT private_key FROM users WHERE id = ?',
                (current_user.id,)
            ).fetchone()['private_key']

            private_key = RSA.import_key(user_private_key_encrypted, passphrase=password)

            encrypted_payload = json.loads(message['body'])

            encrypted_aes_key = _b64d(encrypted_payload['encrypted_aes_key'])
            nonce = _b64d(encrypted_payload['nonce'])
            tag = _b64d(encrypted_payload['tag'])
            ciphertext = _b64d(encrypted_payload['ciphertext'])

            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_session_key = cipher_rsa.decrypt(encrypted_aes_key)

            cipher_aes = AES.new(aes_session_key, AES.MODE_EAX, nonce=nonce)
            decrypted_package_json = cipher_aes.decrypt_and_verify(ciphertext, tag)

            decrypted_data = json.loads(decrypted_package_json.decode('utf-8'))

            signature_status = None
            if encrypted_payload.get("signature"):
                sender_pub_row = db.execute(
                    "SELECT public_key FROM users WHERE id = ?",
                    (message["sender_id"],)
                ).fetchone()

                if sender_pub_row and sender_pub_row["public_key"]:
                    sender_public_key = RSA.import_key(sender_pub_row["public_key"])
                    sig_bytes = _b64d(encrypted_payload["signature"])

                    h = SHA256.new(_signature_message(encrypted_payload))
                    try:
                        pkcs1_15.new(sender_public_key).verify(h, sig_bytes)
                        signature_status = "valid"
                    except (ValueError, TypeError):
                        signature_status = "invalid"
                else:
                    signature_status = "missing_sender_key"
            else:
                signature_status = "not_signed"

            if not message['is_read']:
                db.execute('UPDATE messages SET is_read = 1 WHERE id = ?', (message_id,))
                db.commit()

            return render_template(
                "messages/view_decrypted_message.html",
                message=message,
                decrypted_data=decrypted_data,
                signature_status=signature_status
            )

        except (ValueError, TypeError):
            flash("Could not decrypt message.")
        except Exception:
            flash("An error occurred")

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
        attachment = request.files.get('attachment')

        signing_password = request.form.get("signing_password")

        db = get_db()
        recipient = db.execute('SELECT * FROM users WHERE username = ?', (recipient_username,)).fetchone()

        if recipient is None or recipient['public_key'] is None:
            flash('User not found or user has not set up encryption keys.')
            return redirect(url_for('messages.send_message'))

        try:
            message_data = {
                'body': body,
                'attachment_content': None,
                'attachment_filename': None
            }
            if attachment and attachment.filename != '':
                message_data['attachment_content'] = base64.b64encode(attachment.read()).decode('utf-8')
                message_data['attachment_filename'] = attachment.filename

            plaintext_package = json.dumps(message_data).encode('utf-8')

            recipient_public_key = RSA.import_key(recipient['public_key'])

            aes_session_key = get_random_bytes(16)

            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_session_key)

            cipher_aes = AES.new(aes_session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_package)

            encrypted_payload = {
                'encrypted_aes_key': _b64e(encrypted_aes_key),
                'nonce': _b64e(cipher_aes.nonce),
                'tag': _b64e(tag),
                'ciphertext': _b64e(ciphertext),
            }

            # Podpis cyfrowy (opcjonalny, ale oczekiwany)
            if not signing_password:
                flash("Signing password is required to sign the message.")
                return redirect(url_for('messages.send_message'))

            sender_priv_row = db.execute(
                "SELECT private_key FROM users WHERE id = ?",
                (current_user.id,)
            ).fetchone()
            sender_private_key = RSA.import_key(sender_priv_row["private_key"], passphrase=signing_password)

            h = SHA256.new(_signature_message(encrypted_payload))
            signature = pkcs1_15.new(sender_private_key).sign(h)
            encrypted_payload["signature"] = _b64e(signature)

            db.execute(
                'INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)',
                (current_user.id, recipient['id'], subject, json.dumps(encrypted_payload))
            )
            db.commit()
            flash('Message sent (signed).')
            return redirect(url_for('messages.dashboard'))

        except (ValueError, TypeError):
            flash("Could not sign/encrypt message (wrong signing password?).")
            return redirect(url_for('messages.send_message'))
        except Exception as e:
            print(f"Error during sending: {e}")
            flash("An error occurred during encryption.")
            return redirect(url_for('messages.send_message'))

    return render_template("messages/send_message.html")