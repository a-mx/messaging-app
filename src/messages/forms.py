import re
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from werkzeug.utils import secure_filename

USERNAME_RE = r"^[A-Za-z0-9]+$"
USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 32

SUBJECT_MAX_LEN = 120
BODY_MAX_LEN = 5000

ATTACHMENT_MAX_BYTES = 2 * 1024 * 1024 
ATTACHMENT_NAME_MAX_LEN = 120


class SendMessageForm(FlaskForm):
    recipient = StringField(
        "Recipient",
        validators=[
            DataRequired(message="Recipient is required."),
            Length(
                min=USERNAME_MIN_LEN,
                max=USERNAME_MAX_LEN,
                message=f"Username must be from {USERNAME_MIN_LEN} to {USERNAME_MAX_LEN} characters long.",
            ),
            Regexp(USERNAME_RE, message="Invalid recipient username."),
        ],
    )
    subject = StringField(
        "Subject",
        validators=[
            DataRequired(message="Subject is required."),
            Length(
                max=SUBJECT_MAX_LEN,
                message=f"Subject is too long (max {SUBJECT_MAX_LEN}).",
            ),
        ],
    )
    body = TextAreaField(
        "Message",
        validators=[
            DataRequired(message="Message body is required."),
            Length(
                max=BODY_MAX_LEN,
                message=f"Message body is too long (max {BODY_MAX_LEN}).",
            ),
        ],
    )
    attachment = FileField("Attachment")
    signing_password = PasswordField(
        "Signing password",
        validators=[DataRequired(message="Signing password is required.")],
    )
    submit = SubmitField("Send")

    def validate_attachment(self, field):
        file = field.data
        if not file or not file.filename:
            return

        safe_name = secure_filename(file.filename)
        if not safe_name:
            raise ValidationError("Invalid attachment filename.")

        file.stream.seek(0, 2)
        size = file.stream.tell()
        file.stream.seek(0)

        if size > ATTACHMENT_MAX_BYTES:
            raise ValidationError(
                f"Attachment too large (max {ATTACHMENT_MAX_BYTES // (1024 * 1024)} MiB)."
            )


class DecryptMessageForm(FlaskForm):
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")],
    )
    submit = SubmitField("Decrypt")


class DeleteMessageForm(FlaskForm):
    submit = SubmitField("Delete")