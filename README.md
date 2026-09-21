# Secure Web-Based Password Manager

A course project: a web app where a user logs in with a master password and stores
site credentials (site, username, password) in an encrypted vault. Full design
rationale (architecture diagram, threat model, crypto design, auth model) is in
[`docs/DESIGN.md`](docs/DESIGN.md).

## Scope (Checkpoint 1)

This checkpoint covers **design and repo setup only** — no working app yet.
Implementation starts next checkpoint, following the plan below.

## Planned routes / features

| Route | Method | Purpose |
|-------|--------|---------|
| `/signup` | GET, POST | Create account (derives Argon2id salt, hashes master password) |
| `/login` | GET, POST | Authenticate, regenerate session, redirect to vault |
| `/logout` | POST | Destroy session |
| `/vault` | GET | List the current user's vault entries (site + username only, no secrets shown by default) |
| `/vault/new` | GET, POST | Add a new encrypted entry |
| `/vault/<id>` | GET | Reveal a single decrypted entry (re-checks ownership server-side) |
| `/vault/<id>/edit` | GET, POST | Update an entry |
| `/vault/<id>/delete` | POST | Delete an entry (CSRF-protected) |

Planned, not yet built:
- Rate limiting / lockout on `/login`
- Optional TOTP-based MFA enrollment
- CSP and security headers via `flask-talisman` or equivalent

## Tech stack

Python 3 + Flask, SQLite via SQLAlchemy, `cryptography` (AES-256-GCM), `argon2-cffi`
(key derivation), `bcrypt` (login password hashing), Flask-Login (sessions). Served
over TLS in production via a reverse proxy; local dev uses Flask's adhoc HTTPS cert.
See `docs/DESIGN.md` §3 for the justification.

## Running locally (once implementation starts)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug --cert=adhoc
```

Then open `https://127.0.0.1:5000`.

## Project structure

```
secure-password-manager/
├── docs/
│   └── DESIGN.md        # architecture, threat model, crypto & auth design
├── app/
│   ├── templates/        # Jinja2 templates (auto-escaped)
│   └── static/css/       # styling
├── requirements.txt
└── README.md
```
