"""
Database models (tables).
The database never stores plaintext passwords or encryption keys —
only bcrypt hashes (for login) and AES-GCM ciphertext (for vault entries).
"""

from datetime import datetime, timezone

from flask_login import UserMixin

from . import db


def now_utc():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    # bcrypt hash of the master password — used only to check the login
    password_hash = db.Column(db.String(60), nullable=False)
    # random per-user salt for derive_key() in crypto.py — the key itself is never stored
    kdf_salt = db.Column(db.LargeBinary(16), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc, nullable=False)

    # deleting a user also deletes all their vault entries
    entries = db.relationship("VaultEntry", backref="owner",
                              cascade="all, delete-orphan", lazy=True)


class VaultEntry(db.Model):
    __tablename__ = "vault_entries"

    id = db.Column(db.Integer, primary_key=True)
    # owner of the entry — every query is filtered by this (access control)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    site = db.Column(db.String(255), nullable=False)       # plaintext, shown in list
    username = db.Column(db.String(255), nullable=False)   # plaintext, shown in list
    # the saved password, encrypted with AES-256-GCM (see crypto.encrypt)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=now_utc,
                           onupdate=now_utc, nullable=False)