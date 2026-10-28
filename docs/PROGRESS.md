# Progress Note — Checkpoint 2 (Week 9)

## Implemented

| Requirement | Status | Where |
|---|---|---|
| Web interface with core flows | Done: signup, login, logout, vault list, add, view, edit, delete | `app/templates/`, `app/vault.py` |
| Server-side encryption / decryption | Done: AES-256-GCM per entry, fresh nonce on every encryption; key from PBKDF2-HMAC-SHA256 (600,000 iterations, per-user salt) | `app/crypto.py`, `app/vault.py` |
| Password hashing | Done: bcrypt (cost 12); generic login error and dummy hash against user enumeration | `app/auth.py` |
| Secure session management | Done: session reset on login (fixation), cookies `HttpOnly` + `Secure` + `SameSite=Strict`, 20 min idle / 8 h absolute timeout, vault key kept in server memory only (cookie holds a random token) | `app/__init__.py`, `app/keystore.py`, `app/auth.py` |
| TLS in development | Done: self-signed certificate (`scripts/make_dev_cert.py`), app served on `https://` | `scripts/`, `README.md` |
| Run instructions + incremental commits | Done | `README.md`, git history |

Also in place: CSRF tokens on all forms, server-side validation, ownership
check on every vault query (other users get 404), `Cache-Control: no-store`
on vault pages, Jinja2 auto-escaping (XSS).

## Verified manually

- Database contains only bcrypt hashes and ciphertext. No plaintext passwords.
- Session cookie flags checked in browser DevTools.
- Wrong password and unknown email show the same error message.

## Planned for later checkpoints

- Rate limiting / lockout on login
- Security headers (CSP, HSTS)
- Optional TOTP MFA