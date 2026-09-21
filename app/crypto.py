"""
crypto.py — all the encryption logic for the vault, in one small file.

You are NOT implementing any cryptographic algorithm here. You are only
calling trusted, standard-library / well-audited functions correctly:
  - hashlib.pbkdf2_hmac (built into Python) -> turns a master password into a key
  - cryptography                             -> uses that key to encrypt/decrypt
                                                 vault entries (AES-256-GCM)

Read top to bottom — the functions are used in this order:
    derive_key()  ->  once at signup, and again at every login
    encrypt()     ->  every time a vault entry is saved
    decrypt()     ->  every time a vault entry is viewed
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# 1. Key derivation: master password -> 256-bit key
# ---------------------------------------------------------------------------
#
# Never use the master password directly as a key. Instead we "stretch" it
# with PBKDF2-HMAC-SHA256, run for many iterations on purpose — this is what
# makes brute-forcing a stolen password hash slow and expensive, even for a
# weak password. Each user gets their own random salt so two users with the
# same master password don't end up with the same key.
#
# 600,000 iterations follows OWASP's current PBKDF2-SHA256 recommendation.
# (If your course allows installing argon2-cffi, that's a stronger,
# memory-hard alternative — swap it in here later; nothing else changes.)

PBKDF2_ITERATIONS = 600_000


def generate_salt() -> bytes:
    """Call this ONCE per user, at signup. Store the result (kdf_salt)."""
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Turn (master_password + salt) into a 32-byte (256-bit) key.

    Call this at login (after the user re-types their master password) and
    keep the returned key only in memory for that session — never write it
    to the database or to disk.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,  # 32 bytes = 256 bits, what AES-256 needs
    )


# ---------------------------------------------------------------------------
# 2. Encrypt / decrypt a single vault entry (e.g. a saved password)
# ---------------------------------------------------------------------------
#
# AES-256-GCM does two things at once: it hides the data (confidentiality)
# AND it detects tampering (integrity) — if even one byte of the ciphertext
# is changed, decrypt() raises an error instead of returning garbage.
#
# Every encryption needs a fresh, random "nonce" (12 bytes is standard for
# GCM). You must store the nonce alongside the ciphertext — it's not secret,
# but it must never be reused with the same key.

def encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """
    Encrypt a plaintext string (e.g. a saved password).
    Returns (nonce, ciphertext) — store BOTH in the database row.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """
    Decrypt a vault entry back to plaintext.
    Raises cryptography.exceptions.InvalidTag if the key is wrong or the
    ciphertext was tampered with — always handle that and show a generic
    "couldn't decrypt" error, never a stack trace.
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# 3. Helpers for storing bytes in a normal text DB column
# ---------------------------------------------------------------------------
#
# salt / nonce / ciphertext are all raw bytes. If your DB column is TEXT
# rather than BLOB, base64-encode before saving and decode before use.

def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_b64(data: str) -> bytes:
    return base64.b64decode(data)


# ---------------------------------------------------------------------------
# 4. Quick self-test — run this file directly to see it work end to end:
#       python3 app/crypto.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- signup time ---
    master_password = "correct horse battery staple"
    salt = generate_salt()
    key = derive_key(master_password, salt)

    # --- saving a vault entry ---
    secret_to_store = "MyBankAccountP@ssw0rd"
    nonce, ciphertext = encrypt(key, secret_to_store)
    print("Stored in DB ->",
          "salt:", to_b64(salt),
          "| nonce:", to_b64(nonce),
          "| ciphertext:", to_b64(ciphertext))

    # --- login time, later, entry lookup ---
    key_again = derive_key(master_password, salt)  # re-derived from password + stored salt
    recovered = decrypt(key_again, nonce, ciphertext)
    print("Decrypted ->", recovered)
    assert recovered == secret_to_store
    print("OK: encrypt/decrypt round-trip works.")
