import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError

USERNAME_RE = re.compile(r"^[A-Za-z0-9]+$")
USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 32

PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128
SPECIAL_CHARS_RE = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")


def validate_username(username: str) -> str | None:
    if not username:
        return "Username is required."
    if len(username) < USERNAME_MIN_LEN or len(username) > USERNAME_MAX_LEN:
        return f"Username must be {USERNAME_MIN_LEN}-{USERNAME_MAX_LEN} characters long."
    if not USERNAME_RE.fullmatch(username):
        return "Username may contain only letters and digits (a-zA-Z0-9)."
    return None


def validate_password_strength(password: str) -> str | None:
    password = password or ""

    if len(password) < PASSWORD_MIN_LEN:
        return f"Password must be at least {PASSWORD_MIN_LEN} characters long."
    if len(password) > PASSWORD_MAX_LEN:
        return f"Password must be at most {PASSWORD_MAX_LEN} characters long."
    if not re.search(r"[a-z]", password):
        return "Password must contain lowercase letters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain uppercase letters."
    if not re.search(r"[0-9]", password):
        return "Password must contain digits."
    if not SPECIAL_CHARS_RE.search(password):
        return "Password must contain special characters."
    return None

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(
                min=USERNAME_MIN_LEN,
                max=USERNAME_MAX_LEN,
                message=f"Username must be from {USERNAME_MIN_LEN} to {USERNAME_MAX_LEN} characters long.",
            ),
            Regexp(
                USERNAME_RE,
                message="Username may contain only letters and digits (a-zA-Z0-9).",
            ),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(
                min=PASSWORD_MIN_LEN,
                max=PASSWORD_MAX_LEN,
                message=f"Password must be from {PASSWORD_MIN_LEN} to {PASSWORD_MAX_LEN} characters long.",
            ),
        ],
    )
    submit = SubmitField("Register")

    def validate_password(self, field):
        msg = validate_password_strength(field.data or "")
        if msg:
            raise ValidationError(msg)


class TOTPForm(FlaskForm):
    code = StringField(
        "Code",
        validators=[
            DataRequired(message="Code is required."),
            Length(min=6, max=8, message="Code must be 6 or 8 digits."),
            Regexp(r"^\d+$", message="Invalid code format."),
        ],
    )
    submit = SubmitField("Verify")

    def validate_code(self, field):
        field.data = (field.data or "").strip().replace(" ", "")