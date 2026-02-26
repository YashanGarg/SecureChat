"""
Cryptographic Utilities for SecureChat
Provides AES-256-GCM encryption/decryption and key derivation functions.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# ── Key Derivation ──────────────────────────────────────────────────

def derive_session_key(shared_secret: bytes, info: bytes = b"securechat-session-key") -> bytes:
    """
    Derive a 256-bit AES key from the shared DH secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


# ── AES-256-GCM Encryption ─────────────────────────────────────────

def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a plaintext message using AES-256-GCM.
    Returns: nonce (12 bytes) || ciphertext+tag
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_message(key: bytes, data: bytes) -> str:
    """
    Decrypt an AES-256-GCM encrypted message.
    Expects: nonce (12 bytes) || ciphertext+tag
    """
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# ── RSA Signature Operations ───────────────────────────────────────

def sign_data(private_key, data: bytes) -> bytes:
    """Sign data with RSA private key using PSS padding."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    """Verify an RSA signature using PSS padding."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ── Certificate Utilities ──────────────────────────────────────────

def load_certificate(path: str):
    """Load a PEM certificate from file."""
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())


def load_private_key(path: str, password=None):
    """Load a PEM private key from file."""
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=password)


def certificate_to_pem(cert) -> bytes:
    """Serialize a certificate to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def pem_to_certificate(pem_data: bytes):
    """Deserialize PEM bytes to a certificate object."""
    return load_pem_x509_certificate(pem_data)


def verify_certificate_chain(cert, ca_cert) -> bool:
    """
    Verify that `cert` was signed by `ca_cert`.
    Uses the CA's public key to verify the certificate's signature.
    """
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


# ── Network Framing ────────────────────────────────────────────────

def frame_message(data: bytes) -> bytes:
    """Frame a message with a 4-byte length prefix for TCP transmission."""
    return struct.pack("!I", len(data)) + data


def read_framed_message(sock) -> bytes:
    """Read a length-prefixed framed message from a socket."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return _recv_exact(sock, msg_len)


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from a socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
