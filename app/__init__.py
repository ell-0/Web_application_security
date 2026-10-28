"""
App factory: builds the Flask app.
Later steps will plug in the database, login and vault routes here.
"""

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "Secure Password Manager is running."

    return app