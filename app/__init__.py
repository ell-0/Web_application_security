"""
App factory: builds the Flask app and plugs in
config, database, login handling, CSRF protection, security headers,
error pages and logging.
"""

import logging
import os
import secrets
from datetime import timedelta

from flask import Flask, redirect, render_template, url_for
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Content Security Policy: the browser only runs scripts/styles from our own
# server. Second layer against XSS, in case escaping ever fails.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def create_app(instance_path: str | None = None) -> Flask:
    # instance_path: normally None = the "instance/" folder (git-ignored),
    # which holds the database and the security log. The tests pass a
    # temporary folder here, so they never touch the real database.
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
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
    from .vault import bp as vault_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    with app.app_context():
        db.create_all()   # creates the tables if they don't exist yet

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("vault.list_entries"))
        return redirect(url_for("auth.login"))

    # --- security headers on EVERY response ---
    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = CSP
        return response

    # --- structured security logging (JSON lines in instance/security.log) ---
    from . import security_log
    security_log.setup(app)

    # --- secure error handling: generic page for the user, details in the log ---
    error_messages = {
        400: "Bad request.",
        401: "Please log in.",
        403: "Access denied.",
        404: "Page not found.",
        405: "Method not allowed.",
        413: "Request too large.",
    }

    @app.errorhandler(CSRFError)
    def csrf_error(_e):
        security_log.log_event("csrf_failed", logging.WARNING)
        return render_template("error.html", code=400,
                               message="Your form expired. Please try again."), 400

    @app.errorhandler(HTTPException)
    def http_error(e):
        if e.code in (403, 404):
            security_log.log_event("not_found_or_denied", logging.WARNING, code=e.code)
        return render_template("error.html", code=e.code,
                               message=error_messages.get(e.code, "Something went wrong.")), e.code

    @app.errorhandler(Exception)
    def unexpected_error(e):
        # full stack trace goes to the log; the user only sees a generic page
        security_log.log_event("server_error", logging.ERROR, exc_info=True,
                               error_type=type(e).__name__)
        return render_template("error.html", code=500,
                               message="Something went wrong."), 500

    return app