# Secure Password Manager

ICS0027 Web Application Security, Tallinn University of Technology — Ellen Marie Lasson

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

The database (`instance/vault.db`) and the security log
(`instance/security.log`) are created automatically on first run.

**Optional:** set a fixed session-signing key, so you stay logged in when the
server restarts:

```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

If no `SECRET_KEY` is set, a random one is generated at every start.

## How to use

1. **Sign up** with an email and a master password (at least 12 characters).
2. **Log in.** Your vault opens and shows your saved entries (site and username only).
3. **Add entry:** enter site, username and password. The password is encrypted before it is saved.
4. **Open an entry** to see its password. **Edit** to change it (leave the password field empty to keep the old one), or **Delete** it.
5. **Log out** when done. After 20 minutes without activity you are logged out automatically.

After 5 wrong passwords for the same email, login is blocked for 15 minutes.

## Running the tests

```bash
python -m pytest -v
```

- `tests/test_functionality.py`: normal use works (signup, login, add, view, edit, delete, logout).
- `tests/test_security.py`: attacks fail (SQL injection, XSS, CSP, access to another user's entry, CSRF, error leaks, secrets in logs, brute-force login).

Each test uses its own temporary database, so your real data is not touched.
The latest results are in `docs/test_results.txt`.

## Security features

| Area | How |
|------|-----|
| Credential storage | AES-256-GCM per entry, fresh nonce every time; key derived with PBKDF2-HMAC-SHA256 (600,000 iterations, per-user salt) and kept in server memory only |
| Master password | bcrypt (cost 12); same error for wrong password and unknown email |
| Brute force | 5 failed logins per email or 20 per IP in 15 minutes → login blocked (HTTP 429) |
| Sessions | New session at login; cookie `HttpOnly`, `Secure`, `SameSite=Strict`; 20 min idle / 8 h maximum |
| CSRF | Token on every form (Flask-WTF) |
| SQL injection | SQLAlchemy ORM with parameterized queries only; integer IDs in URLs |
| XSS | Jinja2 auto-escaping; Content Security Policy header on every response |
| Access control | Every vault query filtered by the logged-in user; others get 404 |
| Errors | Debug mode off; generic error pages, details only in the log |
| Logging | JSON lines in `instance/security.log`; never passwords, keys or tokens |
| Transport | TLS (self-signed certificate in development) |

Not implemented yet: optional TOTP multi-factor authentication, HSTS header,
production deployment behind a reverse proxy.

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

## Tech stack

Flask, SQLite + SQLAlchemy, `cryptography` (AES-256-GCM), PBKDF2-HMAC-SHA256
(key derivation), `bcrypt` (login hash), Flask-Login (sessions), Flask-WTF
(forms + CSRF), pytest (tests). TLS: self-signed certificate locally, reverse
proxy in production.

## Project structure

```
├── app/
│   ├── __init__.py       # app factory, config, cookie flags, CSP, error handlers
│   ├── auth.py           # signup / login / logout, session checks
│   ├── vault.py          # vault routes, encryption, ownership checks
│   ├── crypto.py         # PBKDF2-SHA256 key derivation + AES-256-GCM
│   ├── keystore.py       # vault keys in server memory only
│   ├── ratelimit.py      # login brute-force protection
│   ├── security_log.py   # structured JSON security log
│   ├── forms.py          # server-side validation + CSRF
│   ├── models.py         # users, vault_entries tables
│   ├── templates/
│   └── static/css/
├── tests/
│   ├── test_functionality.py
│   └── test_security.py
├── scripts/
│   └── make_dev_cert.py
├── docs/
│   ├── DESIGN.md         # Checkpoint 1: architecture + threat model
│   ├── PROGRESS.md       # Checkpoint 2: progress note
│   └── test_results.txt  # latest test run
└── requirements.txt
```