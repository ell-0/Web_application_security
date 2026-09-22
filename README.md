# Secure Password Manager

Web app: login with master password, store encrypted site/username/password entries.

## Scope (Checkpoint 1)

Design + repo setup only. App will appear at the furthest checkpoints.

## Planned routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/signup` | GET, POST | Create account, derive key salt, hash master password |
| `/login` | GET, POST | Authenticate, regenerate session, redirect to vault |
| `/logout` | POST | Destroy session |
| `/vault` | GET | List entries (site + username only) |
| `/vault/new` | GET, POST | Add entry |
| `/vault/<id>` | GET | Reveal one entry (checks ownership) |
| `/vault/<id>/edit` | GET, POST | Update entry |
| `/vault/<id>/delete` | POST | Delete entry (CSRF-protected) |

Later: rate limiting/lockout on login, optional TOTP MFA, CSP/security headers.

## Tech stack

Flask, SQLite + SQLAlchemy, `cryptography` (AES-256-GCM), PBKDF2-HMAC-SHA256 (key derivation), `bcrypt` (login hash), Flask-Login (sessions), TLS via reverse proxy in prod / adhoc cert locally.

## Running locally

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
│   └── DESIGN.md
├── app/
│   ├── crypto.py
│   ├── templates/
│   └── static/css/
├── requirements.txt
└── README.md
```
