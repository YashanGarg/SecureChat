"""
Certificate Generation Script
Generates a Root CA and two client certificates (Alice & Bob) for the secure chat application.
Trust Chain:  Root CA  ->  Alice Certificate
              Root CA  ->  Bob Certificate
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def generate_rsa_key(key_size=2048):
    """Generate an RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def save_private_key(key, filepath, passphrase=None):
    """Save a private key to a PEM file."""
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode())
        if passphrase
        else serialization.NoEncryption()
    )
    with open(filepath, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc,
        ))
    print(f"  [+] Private key saved: {filepath}")


def save_certificate(cert, filepath):
    """Save a certificate to a PEM file."""
    with open(filepath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  [+] Certificate saved: {filepath}")


def create_root_ca():
    """Create a self-signed Root CA certificate."""
    print("\n[*] Generating Root CA...")
    key = generate_rsa_key(4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SecureState"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    save_private_key(key, os.path.join(CERTS_DIR, "ca_key.pem"))
    save_certificate(cert, os.path.join(CERTS_DIR, "ca_cert.pem"))
    return key, cert


def create_client_certificate(name, ca_key, ca_cert):
    """Create a client certificate signed by the CA."""
    print(f"\n[*] Generating certificate for '{name}'...")
    key = generate_rsa_key(2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SecureState"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    safe_name = name.lower().replace(" ", "_")
    save_private_key(key, os.path.join(CERTS_DIR, f"{safe_name}_key.pem"))
    save_certificate(cert, os.path.join(CERTS_DIR, f"{safe_name}_cert.pem"))
    return key, cert


def add_client_certificate(name):
    """
    Add a new client certificate signed by the existing CA.
    Used when a new participant joins or when deploying to another machine.
    """
    ca_key_path = os.path.join(CERTS_DIR, "ca_key.pem")
    ca_cert_path = os.path.join(CERTS_DIR, "ca_cert.pem")

    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        print("[!] CA certificates not found. Run 'python setup_certs.py' first to generate CA.")
        return None, None

    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate

    with open(ca_key_path, "rb") as f:
        ca_key = load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = load_pem_x509_certificate(f.read())

    return create_client_certificate(name, ca_key, ca_cert)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SecureChat Certificate Generator"
    )
    parser.add_argument(
        "--add-user", type=str, default=None,
        help="Add a new user certificate (e.g., --add-user Charlie). Requires existing CA."
    )
    parser.add_argument(
        "--names", nargs="+", default=None,
        help="Custom names for initial certificate generation (default: Alice Bob)"
    )

    args = parser.parse_args()
    os.makedirs(CERTS_DIR, exist_ok=True)

    # Mode 1: Add a single new user to an existing CA
    if args.add_user:
        print("=" * 60)
        print(f"  Adding certificate for '{args.add_user}'")
        print("=" * 60)
        key, cert = add_client_certificate(args.add_user)
        if key and cert:
            print(f"\n  Certificate for '{args.add_user}' created successfully!")
            print(f"  Now use deploy.py to package files for the remote machine.")
        return

    # Mode 2: Full generation (CA + user certificates)
    names = args.names if args.names else ["Alice", "Bob"]
    print("=" * 60)
    print("  SecureChat Certificate Generator")
    print(f"  Trust Chain: Root CA -> {', '.join(names)}")
    print("=" * 60)

    ca_key, ca_cert = create_root_ca()
    for name in names:
        create_client_certificate(name, ca_key, ca_cert)

    print("\n" + "=" * 60)
    print("  All certificates generated successfully!")
    print(f"  Certificates stored in: {CERTS_DIR}")
    print("=" * 60)
    print("\n  Files created:")
    for f in sorted(os.listdir(CERTS_DIR)):
        print(f"    - {f}")
    print()


if __name__ == "__main__":
    main()
