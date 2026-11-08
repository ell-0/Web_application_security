"""
Security tests for Checkpoint 3.

Each test performs an ATTACK against the app and checks that it FAILS.
Run from the project root:   python -m pytest -v

Every test gets a brand-new app with its own temporary database and log,
so the real instance/vault.db is never touched.
"""

import json
import re

import pytest

from app import create_app, db
from app.models import User, VaultEntry

PASSWORD = "correct-horse-battery"   # master password for test users


# ------------------------------------------------------------------ fixtures

@pytest.fixture
def app(tmp_path):
    """A fresh app whose database and security.log live in a temp folder."""
    return create_app(instance_path=str(tmp_path))


@pytest.fixture
def client(app):
    """A fake browser that talks to the app and keeps its own cookies."""
    return app.test_client()


# ------------------------------------------------------------------- helpers

def get_csrf(client, url):
    """Open a page and take the hidden CSRF token from its HTML,
    the same way a real browser form sends it."""
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html).group(1)


def signup(client, email, password=PASSWORD):
    return client.post("/signup", data={
        "csrf_token": get_csrf(client, "/signup"),
        "email": email, "password": password, "confirm": password,
    })


def login(client, email, password=PASSWORD):
    return client.post("/login", data={
        "csrf_token": get_csrf(client, "/login"),
        "email": email, "password": password,
    })


def make_user(client, email):
    signup(client, email)
    login(client, email)


def add_entry(client, site, username="user1", password="s3cret-pass"):
    return client.post("/vault/new", data={
        "csrf_token": get_csrf(client, "/vault/new"),
        "site": site, "username": username, "password": password,
    })


# ============================================================ SQL INJECTION

SQLI_PAYLOADS = [
    "' OR '1'='1",              # classic "always true" condition
    "' OR 1=1 --",              # always true + comment out the rest
    "admin'--",                 # comment out the password check
    "'; DROP TABLE users; --",  # stacked query: try to delete a table
    '" OR ""="',                # same idea with double quotes
]


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_login_bypass_fails(app, client, payload):
    """Attack: SQL payload in the login form to log in without a password."""
    signup(client, "victim@test.com")

    r1 = login(client, payload, payload)              # payload as email + password
    r2 = login(client, "victim@test.com", payload)    # real email, payload as password

    assert b"Invalid email or password." in r1.data
    assert b"Invalid email or password." in r2.data
    assert client.get("/vault/").status_code == 302   # still not logged in -> redirect
    with app.app_context():
        assert User.query.count() == 1                # users table still intact


@pytest.mark.parametrize("payload", SQLI_PAYLOADS)
def test_sqli_payload_stored_as_plain_text(app, client, payload):
    """Attack: SQL payload in a vault field. With parameterized queries it is
    saved as ordinary text and never executed."""
    make_user(client, "alice@test.com")
    add_entry(client, site=payload)

    with app.app_context():
        assert VaultEntry.query.filter_by(site=payload).count() == 1
        assert User.query.count() == 1                # DROP TABLE did not run


def test_sqli_in_url_is_rejected(client):
    """Attack: SQL in the entry id. The <int:...> route only accepts numbers."""
    make_user(client, "alice@test.com")
    assert client.get("/vault/1%20OR%201=1").status_code == 404


# ===================================================================== XSS

def test_xss_payload_is_escaped(client):
    """Attack: save HTML/JavaScript as an entry. It must come back as harmless
    text (&lt;script&gt;), not as a real <script> tag."""
    script = '<script>alert("xss")</script>'
    img = "<img src=x onerror=alert(1)>"
    make_user(client, "alice@test.com")
    add_entry(client, site=script, username=img)

    html = client.get("/vault/").get_data(as_text=True)
    assert script not in html
    assert img not in html
    assert "&lt;script&gt;" in html


def test_csp_header_present(client):
    """Second XSS layer: browser is told to run only our own scripts."""
    csp = client.get("/login").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


# ========================================================== ACCESS CONTROL

def test_other_user_cannot_read_edit_or_delete_entry(app):
    """Attack (IDOR): Bob changes the id in the URL to reach Alice's entry."""
    alice = app.test_client()
    bob = app.test_client()

    make_user(alice, "alice@test.com")
    add_entry(alice, site="alice-bank", password="alice-secret")
    with app.app_context():
        entry_id = VaultEntry.query.filter_by(site="alice-bank").one().id

    make_user(bob, "bob@test.com")
    token = get_csrf(bob, "/vault/")

    # read
    r = bob.get(f"/vault/{entry_id}")
    assert r.status_code == 404
    assert b"alice-secret" not in r.data
    # edit
    assert bob.get(f"/vault/{entry_id}/edit").status_code == 404
    assert bob.post(f"/vault/{entry_id}/edit", data={
        "csrf_token": token, "site": "hacked", "username": "x", "password": ""
    }).status_code == 404
    # delete
    assert bob.post(f"/vault/{entry_id}/delete",
                    data={"csrf_token": token}).status_code == 404
    # not in Bob's list either
    assert b"alice-bank" not in bob.get("/vault/").data

    # Alice's entry is unchanged and still hers
    with app.app_context():
        assert db.session.get(VaultEntry, entry_id).site == "alice-bank"
    r = alice.get(f"/vault/{entry_id}")
    assert r.status_code == 200
    assert b"alice-secret" in r.data


def test_logged_out_user_cannot_open_vault(client):
    """Attack: open the vault without logging in."""
    r = client.get("/vault/1")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


# ===================================================================== CSRF

def test_post_without_csrf_token_is_rejected(app, client):
    """Attack: a forged delete request with no CSRF token."""
    make_user(client, "alice@test.com")
    add_entry(client, site="keep-me")
    with app.app_context():
        entry_id = VaultEntry.query.filter_by(site="keep-me").one().id

    r = client.post(f"/vault/{entry_id}/delete", data={})
    assert r.status_code == 400
    with app.app_context():
        assert db.session.get(VaultEntry, entry_id) is not None   # not deleted


# =========================================================== ERROR HANDLING

def test_404_page_leaks_nothing(client):
    r = client.get("/does-not-exist")
    body = r.get_data(as_text=True)
    assert r.status_code == 404
    for leak in ("Traceback", "werkzeug", "sqlalchemy", "File \""):
        assert leak not in body


def test_crash_shows_generic_page_and_is_logged(app, tmp_path):
    """Force a server error: the user sees a generic page,
    the details go only to the log."""
    @app.route("/boom")
    def boom():
        raise RuntimeError("secret internal detail")

    r = app.test_client().get("/boom")
    assert r.status_code == 500
    assert b"Something went wrong" in r.data
    assert b"secret internal detail" not in r.data
    assert b"Traceback" not in r.data

    log = (tmp_path / "security.log").read_text()
    assert "server_error" in log
    assert "RuntimeError" in log


# ================================================================= LOGGING

def test_log_is_json_and_contains_no_secrets(client, tmp_path):
    signup(client, "alice@test.com")
    login(client, "alice@test.com", "wrong-password-123")   # failed login
    login(client, "alice@test.com")                         # successful login
    add_entry(client, site="bank", password="vault-secret-xyz")

    text = (tmp_path / "security.log").read_text()
    events = [json.loads(line)["event"] for line in text.splitlines()]  # every line is valid JSON

    assert "login_failed" in events
    assert "login_success" in events
    assert "entry_created" in events
    for secret in (PASSWORD, "wrong-password-123", "vault-secret-xyz"):
        assert secret not in text