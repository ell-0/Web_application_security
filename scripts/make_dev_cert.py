"""
Creates a self-signed TLS certificate for LOCAL DEVELOPMENT only.

Output (git-ignored):
    certs/dev-cert.pem  -> the certificate (public)
    certs/dev-key.pem   -> the private key (secret, file permissions 600)

Run once:   python3 scripts/make_dev_cert.py
"""

import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(PROJECT_ROOT, "certs")
CERT_PATH = os.path.join(CERT_DIR, "dev-cert.pem")
KEY_PATH = os.path.join(CERT_DIR, "dev-key.pem")


def main() -> None:
    os.makedirs(CERT_DIR, exist_ok=True)

    # 1. A new private key (elliptic curve P-256 — modern and fast)
    key = ec.generate_private_key(ec.SECP256R1())

    # 2. The certificate: "this public key belongs to localhost / 127.0.0.1".
    #    Self-signed = we sign it ourselves, so browsers will warn once.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # 3. Save the certificate (public)
    with open(CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # 4. Save the private key, readable only by you (permissions 600)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))

    print("Created", CERT_PATH)
    print("Created", KEY_PATH)


if __name__ == "__main__":
    main()