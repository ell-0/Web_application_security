# Secure Password Manager

Web app: log in with a master password, store site / username / password
entries. Saved passwords are encrypted on the server with AES-256-GCM.

## Requirements

- Python 3.10 or newer
- Git

## Run locally (clean machine)

```bash
git clone https://github.com/ell-0/Web_application_security.git
cd Web_application_security

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

python3 scripts/make_dev_cert.py  # creates certs/ (self-signed TLS cert, git-ignored)
flask --app app run --cert=certs/dev-cert.pem --key=certs/dev-key.pem
```

Open **https://127.0.0.1:5000**. The browser warns once because the
development certificate is self-signed. Choose *Advanced → Proceed*.
Traffic is still encrypted with TLS.

The database (`instance/vault.db`) is created automatically on first run.

**Optional:** set a fixed session-signing key, so you stay logged in when the
server restarts:

```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

If no `SECRET_KEY` is set, a random one is generated at every start.

## Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/signup` | GET, POST | Create account (bcrypt hash + per-user KDF salt) |
| `/login` | GET, POST | Authenticate, reset session, derive vault key |
| `/logout` | POST | Forget vault key, clear session (CSRF-protected) |
| `/vault/` | GET | List entries (site + username only) |
| `/vault/new` | GET, POST | Add entry (password encrypted before saving) |
| `/vault/<id>` | GET | View one entry, decrypted (owner only) |
| `/vault/<id>/edit` | GET, POST | Update entry (owner only) |
| `/vault/<id>/delete` | POST | Delete entry (owner only, CSRF-protected) |

Later: rate limiting/lockout on login, optional TOTP MFA, CSP/security headers.

## Tech stack

Flask, SQLite + SQLAlchemy, `cryptography` (AES-256-GCM), PBKDF2-HMAC-SHA256
(key derivation), `bcrypt` (login hash), Flask-Login (sessions), Flask-WTF
(forms + CSRF). TLS: self-signed certificate locally, reverse proxy in production.

## Project structure

```
├── app/
│   ├── __init__.py     # app factory, config, cookie flags
│   ├── auth.py         # signup / login / logout, session checks
│   ├── vault.py        # vault routes, encryption, ownership checks
│   ├── crypto.py       # PBKDF2-SHA256 key derivation + AES-256-GCM
│   ├── keystore.py     # vault keys in server memory only
│   ├── forms.py        # server-side validation + CSRF
│   ├── models.py       # users, vault_entries tables
│   ├── templates/
│   └── static/css/
├── scripts/
│   └── make_dev_cert.py
├── docs/
│   ├── DESIGN.md       # Checkpoint 1: architecture + threat model
│   └── PROGRESS.md     # Checkpoint 2: progress note
└── requirements.txt
```