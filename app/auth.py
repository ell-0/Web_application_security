"""
Authentication: signup, login, logout, and session checks.
"""

import bcrypt
from flask import Blueprint, flash, redirect, render_template, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from . import db, keystore, login_manager
from .crypto import derive_key, generate_salt
from .forms import LoginForm, SignupForm
from .models import User

bp = Blueprint("auth", __name__)

# Used when the email doesn't exist, so a failed login takes the same time
# either way — otherwise an attacker could tell which emails are registered.
DUMMY_HASH = bcrypt.hashpw(b"not-a-real-password", bcrypt.gensalt(12))


@login_manager.user_loader
def load_user(user_id: str):
    """Flask-Login calls this on each request to get the logged-in user
    from the user id stored in the session."""
    return db.session.get(User, int(user_id))


@bp.before_app_request
def check_vault_session():
    """On every request: a logged-in user must still have a valid vault key.
    If it expired (idle/absolute timeout or server restart) -> log out."""
    if current_user.is_authenticated:
        if keystore.get(session.get("vault_token"), current_user.id) is None:
            logout_user()
            session.clear()
            flash("Your session expired. Please log in again.")
            return redirect(url_for("auth.login"))


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.")
            return render_template("signup.html", form=form)

        password = form.password.data.encode("utf-8")
        user = User(
            email=email,
            # bcrypt: slow, salted hash — for checking the login
            password_hash=bcrypt.hashpw(password, bcrypt.gensalt(12)).decode("ascii"),
            # salt for derive_key() — for the vault encryption key
            kdf_salt=generate_salt(),
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.")
        return redirect(url_for("auth.login"))
    return render_template("signup.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        stored_hash = user.password_hash.encode("ascii") if user else DUMMY_HASH
        password_ok = bcrypt.checkpw(password.encode("utf-8")[:72], stored_hash)

        if user is None or not password_ok:
            # same message for "no such user" and "wrong password"
            flash("Invalid email or password.")
            return render_template("login.html", form=form)

        # --- successful login ---
        session.clear()                 # throw away the old session (fixation)
        login_user(user, remember=False)
        session.permanent = True        # applies the 8-hour lifetime

        # derive the vault key from the master password and keep it in
        # server memory only; the cookie gets just a random token
        key = derive_key(password, user.kdf_salt)
        session["vault_token"] = keystore.put(user.id, key)
        return redirect(url_for("index"))

    return render_template("login.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    keystore.drop(session.get("vault_token"))  # forget the vault key
    logout_user()
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("auth.login"))