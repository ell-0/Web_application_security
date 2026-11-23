"""
Functionality tests: normal user actions must WORK.
(The security tests in test_security.py check that attacks FAIL.)

Run from the project root:   python -m pytest -v
"""

import re

import pytest

from app import create_app, db, ratelimit
from app.models import User, VaultEntry

PASSWORD = "correct-horse-battery"


@pytest.fixture
def app(tmp_path):
    """Fresh app with its own temporary database and log."""
    ratelimit.clear()
    return create_app(instance_path=str(tmp_path))


@pytest.fixture
def client(app):
    return app.test_client()


def get_csrf(client, url):
    html = client.get(url).get_data(as_text=True)
    return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html).group(1)


def signup(client, email, password=PASSWORD, confirm=None):
    return client.post("/signup", data={
        "csrf_token": get_csrf(client, "/signup"),
        "email": email, "password": password,
        "confirm": password if confirm is None else confirm,
    }, follow_redirects=True)


def login(client, email, password=PASSWORD):
    return client.post("/login", data={
        "csrf_token": get_csrf(client, "/login"),
        "email": email, "password": password,
    }, follow_redirects=True)


def add_entry(client, site="github.com", username="ellen", password="s3cret-pass"):
    return client.post("/vault/new", data={
        "csrf_token": get_csrf(client, "/vault/new"),
        "site": site, "username": username, "password": password,
    }, follow_redirects=True)


def entry_id(app, site):
    with app.app_context():
        return VaultEntry.query.filter_by(site=site).one().id


# ------------------------------------------------------------ accounts

def test_signup_and_login_work(app, client):
    r = signup(client, "ellen@test.com")
    assert b"Account created" in r.data

    r = login(client, "ellen@test.com")
    assert r.status_code == 200
    assert client.get("/vault/").status_code == 200     # vault is open


def test_signup_rejects_short_password(app, client):
    signup(client, "ellen@test.com", password="short")
    with app.app_context():
        assert User.query.count() == 0


def test_signup_rejects_mismatched_confirmation(app, client):
    signup(client, "ellen@test.com", confirm="something-else-123")
    with app.app_context():
        assert User.query.count() == 0


# ------------------------------------------------------------ vault

def test_add_and_view_entry(app, client):
    signup(client, "ellen@test.com")
    login(client, "ellen@test.com")
    add_entry(client, site="github.com", password="s3cret-pass")

    # shown in the list (site only, not the password)
    listing = client.get("/vault/").data
    assert b"github.com" in listing
    assert b"s3cret-pass" not in listing

    # opening the entry shows the decrypted password
    eid = entry_id(app, "github.com")
    assert b"s3cret-pass" in client.get(f"/vault/{eid}").data

    # the database holds only ciphertext, not the password
    with app.app_context():
        assert b"s3cret-pass" not in db.session.get(VaultEntry, eid).ciphertext


def test_edit_entry(app, client):
    signup(client, "ellen@test.com")
    login(client, "ellen@test.com")
    add_entry(client, site="old-site.com", password="old-pass")
    eid = entry_id(app, "old-site.com")

    # change site and password
    client.post(f"/vault/{eid}/edit", data={
        "csrf_token": get_csrf(client, f"/vault/{eid}/edit"),
        "site": "new-site.com", "username": "ellen", "password": "new-pass",
    })
    page = client.get(f"/vault/{eid}").data
    assert b"new-site.com" in page
    assert b"new-pass" in page

    # empty password field = keep the old password
    client.post(f"/vault/{eid}/edit", data={
        "csrf_token": get_csrf(client, f"/vault/{eid}/edit"),
        "site": "new-site.com", "username": "ellen2", "password": "",
    })
    page = client.get(f"/vault/{eid}").data
    assert b"ellen2" in page
    assert b"new-pass" in page


def test_delete_entry(app, client):
    signup(client, "ellen@test.com")
    login(client, "ellen@test.com")
    add_entry(client, site="delete-me.com")
    eid = entry_id(app, "delete-me.com")

    client.post(f"/vault/{eid}/delete",
                data={"csrf_token": get_csrf(client, f"/vault/{eid}")})

    with app.app_context():
        assert VaultEntry.query.count() == 0
    assert b"delete-me.com" not in client.get("/vault/").data


def test_logout(client):
    signup(client, "ellen@test.com")
    login(client, "ellen@test.com")

    client.post("/logout", data={"csrf_token": get_csrf(client, "/vault/")})

    r = client.get("/vault/")
    assert r.status_code == 302                 # sent back to login
    assert "/login" in r.headers["Location"]