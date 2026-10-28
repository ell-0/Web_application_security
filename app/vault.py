"""
Vault: list, add, view, edit and delete saved passwords.

Security rules used in every route:
  - @login_required: only logged-in users get in.
  - Every query is filtered by user_id = current_user.id, so a user can
    never read or change someone else's entry, even by changing the id in
    the URL (Broken Access Control / IDOR).
  - Passwords are encrypted with the user's vault key before saving and
    decrypted only when the user opens that one entry.
"""

from cryptography.exceptions import InvalidTag
from flask import Blueprint, abort, flash, redirect, render_template, session, url_for
from flask_login import current_user, login_required

from . import db, keystore
from .crypto import decrypt, encrypt
from .forms import DeleteForm, EntryForm
from .models import VaultEntry

bp = Blueprint("vault", __name__, url_prefix="/vault")


def current_key() -> bytes:
    """The logged-in user's vault key, from server memory."""
    key = keystore.get(session.get("vault_token"), current_user.id)
    if key is None:          # normally caught earlier by check_vault_session
        abort(401)
    return key


def get_own_entry(entry_id: int) -> VaultEntry:
    """Load an entry ONLY if it belongs to the logged-in user, else 404.
    (404 instead of 403, so others can't even learn the entry exists.)"""
    entry = VaultEntry.query.filter_by(id=entry_id, user_id=current_user.id).first()
    if entry is None:
        abort(404)
    return entry


@bp.after_request
def no_cache(response):
    # Vault pages contain secrets: tell the browser not to store them
    # (so they can't be seen later via the Back button or the disk cache).
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/")
@login_required
def list_entries():
    entries = (VaultEntry.query.filter_by(user_id=current_user.id)
               .order_by(VaultEntry.site).all())
    # the list shows only site + username — passwords stay encrypted
    return render_template("vault.html", entries=entries)


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new_entry():
    form = EntryForm()
    if form.validate_on_submit():
        if not form.password.data:
            form.password.errors.append("Password is required.")
            return render_template("entry_form.html", form=form, title="Add entry")
        nonce, ciphertext = encrypt(current_key(), form.password.data)
        entry = VaultEntry(
            user_id=current_user.id,   # owner comes from the session, never from the form
            site=form.site.data.strip(),
            username=form.username.data.strip(),
            nonce=nonce,
            ciphertext=ciphertext,
        )
        db.session.add(entry)
        db.session.commit()
        flash("Entry saved.")
        return redirect(url_for("vault.list_entries"))
    return render_template("entry_form.html", form=form, title="Add entry")


@bp.route("/<int:entry_id>")
@login_required
def view_entry(entry_id):
    entry = get_own_entry(entry_id)
    try:
        password = decrypt(current_key(), entry.nonce, entry.ciphertext)
    except InvalidTag:
        # wrong key or tampered ciphertext — show a generic message, no details
        password = None
        flash("This entry could not be decrypted.")
    return render_template("entry_view.html", entry=entry, password=password,
                           delete_form=DeleteForm())


@bp.route("/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id):
    entry = get_own_entry(entry_id)
    form = EntryForm(obj=entry)   # pre-fill site + username
    if form.validate_on_submit():
        entry.site = form.site.data.strip()
        entry.username = form.username.data.strip()
        if form.password.data:    # empty = keep the old password
            # new nonce every time we encrypt — never reuse one
            entry.nonce, entry.ciphertext = encrypt(current_key(), form.password.data)
        db.session.commit()
        flash("Entry updated.")
        return redirect(url_for("vault.view_entry", entry_id=entry.id))
    return render_template("entry_form.html", form=form, title="Edit entry", editing=True)


@bp.route("/<int:entry_id>/delete", methods=["POST"])
@login_required
def delete_entry(entry_id):
    form = DeleteForm()
    if not form.validate_on_submit():   # missing/wrong CSRF token
        abort(400)
    entry = get_own_entry(entry_id)
    db.session.delete(entry)
    db.session.commit()
    flash("Entry deleted.")
    return redirect(url_for("vault.list_entries"))