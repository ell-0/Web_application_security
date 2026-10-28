"""
App factory: builds the Flask app.
Later steps will plug in login and vault routes here.
"""

import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app() -> Flask:
    # instance_relative_config: the "instance/" folder (git-ignored)
    # holds private runtime files, like the database
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + os.path.join(app.instance_path, "vault.db")
    )

    db.init_app(app)

    from . import models  # noqa: F401 — registers the tables

    with app.app_context():
        db.create_all()   # creates the tables if they don't exist yet

    @app.route("/")
    def index():
        return "Secure Password Manager is running."

    return app