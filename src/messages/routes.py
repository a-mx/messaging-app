import base64
import json

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request, current_app
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from src.extensions import db
from src.models.user import User
from src.messages import messages_bp
from src.models.messages import Message

from src.messages.forms import (
    SendMessageForm, DecryptMessageForm, DeleteMessageForm,
    ATTACHMENT_NAME_MAX_LEN,
)


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def signature_message(encrypted_payload: dict) -> bytes:
    parts = [
        encrypted_payload["encrypted_aes_key"],
        encrypted_payload["nonce"],
        encrypted_payload["tag"],
        encrypted_payload["ciphertext"],
    ]
    return ("|".join(parts)).encode("utf-8")

@messages_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("messages/dashboard.html")


@messages_bp.route("/messages")
@login_required
def messages():
    user_messages = (
        Message.query
        .filter_by(recipient_id=current_user.id)
        .order_by(Message.timestamp.desc())
        .all()
    )
    return render_template("messages/messages.html", messages=user_messages)


@messages_bp.route("/message/<int:message_id>", methods=["GET", "POST"])
@login_required
def view_message(message_id):
    message = Message.query.filter_by(
        id=message_id, recipient_id=current_user.id
    ).first()

    if message is None:
        flash("Message not found or you don't have access.")
        return redirect(url_for("messages.messages"))

    form = DecryptMessageForm()

    if form.validate_on_submit():
        try:
            private_key = RSA.import_key(
                current_user.private_key, passphrase=form.password.data
            )

            encrypted_payload = json.loads(message.body)

            encrypted_aes_key = b64d(encrypted_payload["encrypted_aes_key"])
            nonce = b64d(encrypted_payload["nonce"])
            tag = b64d(encrypted_payload["tag"])
            ciphertext = b64d(encrypted_payload["ciphertext"])

            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_session_key = cipher_rsa.decrypt(encrypted_aes_key)

            cipher_aes = AES.new(aes_session_key, AES.MODE_GCM, nonce=nonce)
            decrypted_package_json = cipher_aes.decrypt_and_verify(ciphertext, tag)
            decrypted_data = json.loads(decrypted_package_json.decode("utf-8"))

            signature_status = _verify_signature(message, encrypted_payload)

            if not message.is_read:
                message.is_read = True
                db.session.commit()

            return render_template(
                "messages/view_decrypted_message.html",
                message=message,
                decrypted_data=decrypted_data,
                signature_status=signature_status,
            )

        except (ValueError, TypeError):
            flash("Could not decrypt message.")
        except Exception:
            current_app.logger.exception("view_message decryption failed")
            flash("An error occurred.")

    return render_template(
        "messages/view_message.html", message=message, form=form
    )


def _verify_signature(message: Message, encrypted_payload: dict) -> str:
    if not encrypted_payload.get("signature"):
        return "not_signed"

    sender_pub = message.sender.public_key if message.sender else None
    if not sender_pub:
        return "missing_sender_key"

    try:
        sender_public_key = RSA.import_key(sender_pub)
        sig_bytes = b64d(encrypted_payload["signature"])
        h = SHA256.new(signature_message(encrypted_payload))
        pkcs1_15.new(sender_public_key).verify(h, sig_bytes)
        return "valid"
    except Exception:
        return "invalid"


@messages_bp.route("/message/<int:message_id>/delete", methods=["POST"])
@login_required
def delete_message(message_id):
    form = DeleteMessageForm()
    if not form.validate_on_submit():
        flash("Invalid request.")
        return redirect(url_for("messages.messages"))

    message = Message.query.filter_by(
        id=message_id, recipient_id=current_user.id
    ).first()

    if message:
        db.session.delete(message)
        db.session.commit()
        flash("Message deleted.")
    else:
        flash("Could not delete this message.")

    return redirect(url_for("messages.messages"))


@messages_bp.route("/send", methods=["GET", "POST"])
@login_required
def send_message():
    form = SendMessageForm()

    if form.validate_on_submit():
        recipient_username = form.recipient.data.strip()
        subject = form.subject.data.strip()
        body = form.body.data or ""
        signing_password = form.signing_password.data

        attachment = form.attachment.data
        safe_name = None
        content = None
        if attachment and attachment.filename:
            safe_name = secure_filename(attachment.filename)[:ATTACHMENT_NAME_MAX_LEN]
            content = attachment.read()

        recipient = User.query.filter_by(username=recipient_username).first()
        if recipient is None or recipient.public_key is None:
            flash("Message sent.")
            return redirect(url_for("messages.send_message"))

        try:
            message_data = {
                "body": body,
                "attachment_content": None,
                "attachment_filename": None,
            }
            if content is not None and safe_name is not None:
                message_data["attachment_content"] = base64.b64encode(content).decode("utf-8")
                message_data["attachment_filename"] = safe_name

            plaintext_package = json.dumps(message_data).encode("utf-8")

            recipient_public_key = RSA.import_key(recipient.public_key)

            aes_session_key = get_random_bytes(16)

            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_session_key)

            cipher_aes = AES.new(aes_session_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext_package)

            encrypted_payload = {
                "encrypted_aes_key": b64e(encrypted_aes_key),
                "nonce": b64e(cipher_aes.nonce),
                "tag": b64e(tag),
                "ciphertext": b64e(ciphertext),
            }

            sender_private_key = RSA.import_key(
                current_user.private_key, passphrase=signing_password
            )
            h = SHA256.new(signature_message(encrypted_payload))
            signature = pkcs1_15.new(sender_private_key).sign(h)
            encrypted_payload["signature"] = b64e(signature)

            msg = Message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                subject=subject,
                body=json.dumps(encrypted_payload),
            )
            db.session.add(msg)
            db.session.commit()

            flash("Message sent.")
            return redirect(url_for("messages.dashboard"))

        except (ValueError, TypeError):
            db.session.rollback()
            flash("Could not sign/encrypt message.")
            return redirect(url_for("messages.send_message"))
        except Exception:
            db.session.rollback()
            current_app.logger.exception("send_message encryption failed")
            flash("An error occurred during encryption.")
            return redirect(url_for("messages.send_message"))

    if request.method == "POST" and form.errors:
        for field, errs in form.errors.items():
            for err in errs:
                flash(f"{field}: {err}")

    return render_template("messages/send_message.html", form=form)