"""
App factory: builds the Flask app and plugs in
config, database, login handling, CSRF protection and routes.
"""

import os
import secrets
from datetime import timedelta

from flask import Flask, redirect, render_template, url_for
from flask_login import LoginManager, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()


def create_app() -> Flask:
    # instance_relative_config: the "instance/" folder (git-ignored)
    # holds private runtime files, like the database
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        # Signs the session cookie so users can't forge or edit it.
        # Taken from the environment; if missing, a random one is made at
        # startup (then everyone is logged out on restart — fine for dev).
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(app.instance_path, "vault.db"),
        # --- session cookie flags ---
        SESSION_COOKIE_HTTPONLY=True,      # JavaScript can't read it (XSS can't steal it)
        SESSION_COOKIE_SECURE=True,        # only sent over HTTPS
        SESSION_COOKIE_SAMESITE="Strict",  # not sent from other sites (CSRF)
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # absolute maximum
        WTF_CSRF_TIME_LIMIT=None,          # CSRF token valid for the whole session
        MAX_CONTENT_LENGTH=64 * 1024,      # reject huge request bodies
    )

    db.init_app(app)
    csrf.init_app(app)            # every POST form must carry a valid CSRF token
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in first."
    # if the session cookie shows up from a different browser/IP, drop it
    login_manager.session_protection = "strong"

    from . import models  # noqa: F401 — registers the tables
    from .auth import bp as auth_bp

    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()   # creates the tables if they don't exist yet

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("home"))
        return redirect(url_for("auth.login"))

    @app.route("/home")
    @login_required
    def home():
        # temporary page — replaced by the vault in the next step
        return render_template("home.html")

    return app