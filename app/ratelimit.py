"""
Login rate limiting: slows down password guessing (brute force).

Failed logins are counted per email AND per IP address, in server memory.
After too many failures inside the time window, further login attempts
are refused before the password is even checked.
"""

import threading
import time

WINDOW = 15 * 60      # count failures from the last 15 minutes
MAX_PER_EMAIL = 5     # guesses against one account
MAX_PER_IP = 20       # one client trying many accounts

_failures: dict[str, list[float]] = {}   # key -> times of failed logins
_lock = threading.Lock()                 # requests run in parallel threads


def _recent(key: str, now: float) -> list[float]:
    """Failures for this key inside the window; forgets older ones."""
    times = [t for t in _failures.get(key, []) if now - t < WINDOW]
    if times:
        _failures[key] = times
    else:
        _failures.pop(key, None)
    return times


def is_blocked(email: str, ip: str) -> bool:
    now = time.time()
    with _lock:
        return (len(_recent("email:" + email, now)) >= MAX_PER_EMAIL
                or len(_recent("ip:" + ip, now)) >= MAX_PER_IP)


def record_failure(email: str, ip: str) -> None:
    now = time.time()
    with _lock:
        for key in ("email:" + email, "ip:" + ip):
            _failures.setdefault(key, []).append(now)


def reset(email: str) -> None:
    """Called after a successful login."""
    with _lock:
        _failures.pop("email:" + email, None)


def clear() -> None:
    """Forget everything (used by the tests)."""
    with _lock:
        _failures.clear()