"""
Forms. Flask-WTF adds a hidden CSRF token to each form and checks it on
submit. All validation here runs on the SERVER — anything the browser
checks is only for convenience and can be bypassed.
"""

from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp, ValidationError


def max_72_bytes(form, field):
    # bcrypt only uses the first 72 BYTES of a password (and newer versions
    # refuse longer ones). Some characters (õ, ä, emoji) take 2–4 bytes each.
    if len(field.data.encode("utf-8")) > 72:
        raise ValidationError("Password is too long (max 72 bytes).")


class SignupForm(FlaskForm):
    email = EmailField("Email", validators=[
        DataRequired(), Length(max=254),
        Regexp(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", message="Enter a valid email."),
    ])
    password = PasswordField("Master password", validators=[
        DataRequired(), Length(min=12, message="Use at least 12 characters."), max_72_bytes,
    ])
    confirm = PasswordField("Repeat master password", validators=[
        DataRequired(), EqualTo("password", message="Passwords don't match."),
    ])


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Length(max=254)])
    password = PasswordField("Master password", validators=[DataRequired(), Length(max=200)])