"""
keystore.py — keeps each logged-in user's vault key in SERVER memory.

Why not put the key in the session cookie?
Flask's session cookie is only SIGNED, not encrypted: the browser (and
anyone who steals the cookie) can read what's inside. So the cookie only
holds a random token, and the real key stays here, on the server.

Keys are never written to disk. They disappear on logout, after the
idle / absolute timeout, or when the server restarts (then the user
simply logs in again).
"""

import secrets
import threading
import time

IDLE_TIMEOUT = 20 * 60         # 20 minutes without activity
ABSOLUTE_TIMEOUT = 8 * 60 * 60  # 8 hours max, even if active

_store = {}               # token -> {"user_id", "key", "created", "last_used"}
_lock = threading.Lock()  # the dev server handles requests in parallel threads


def put(user_id: int, key: bytes) -> str:
    """Store a key at login. Returns the random token to put in the session."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _store[token] = {"user_id": user_id, "key": key,
                         "created": now, "last_used": now}
    return token


def get(token: str | None, user_id: int) -> bytes | None:
    """Return the key if the token is valid, belongs to this user and hasn't expired."""
    if not token:
        return None
    now = time.time()
    with _lock:
        entry = _store.get(token)
        if entry is None or entry["user_id"] != user_id:
            return None
        if (now - entry["last_used"] > IDLE_TIMEOUT
                or now - entry["created"] > ABSOLUTE_TIMEOUT):
            del _store[token]
            return None
        entry["last_used"] = now
        return entry["key"]


def drop(token: str | None) -> None:
    """Forget a key (logout)."""
    if token:
        with _lock:
            _store.pop(token, None)