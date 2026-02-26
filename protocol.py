"""
Custom Key Exchange Protocol: CertDH
(Certificate-Authenticated Diffie-Hellman)

This module implements a custom key exchange protocol that does NOT use TLS.
It combines X.509 certificate-based authentication with Diffie-Hellman key
exchange to establish a shared secret between two parties.

Protocol Steps:
  Step 1 (Initiator → Responder):  HELLO  | Initiator's Certificate (PEM)
  Step 2 (Responder → Initiator):  HELLO_ACK | Responder's Certificate (PEM)
  Step 3: Both sides verify the peer's certificate against the trusted CA
  Step 4 (Initiator → Responder):  DH_PARAMS | p | g | g^a mod p | Signature_Initiator
  Step 5 (Responder → Initiator):  DH_REPLY  | g^b mod p | Signature_Responder
  Step 6: Both sides verify DH signatures and compute shared secret g^(ab) mod p
  Step 7: Derive AES-256 session key from shared secret via HKDF

All messages are length-prefixed and use JSON for structured fields.
"""

import os
import json
import secrets
from cryptography.hazmat.primitives import hashes

from crypto_utils import (
    sign_data,
    verify_signature,
    verify_certificate_chain,
    certificate_to_pem,
    pem_to_certificate,
    derive_session_key,
    frame_message,
    read_framed_message,
)


# ── Diffie-Hellman Parameters ──────────────────────────────────────
# Using a 2048-bit MODP group (RFC 3526 Group 14) for DH key exchange
# This is a well-known safe prime; we generate our OWN protocol around it.

DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
DH_GENERATOR = 2


# ── Protocol Message Types ─────────────────────────────────────────

MSG_HELLO     = "HELLO"
MSG_HELLO_ACK = "HELLO_ACK"
MSG_DH_PARAMS = "DH_PARAMS"
MSG_DH_REPLY  = "DH_REPLY"
MSG_CHAT      = "CHAT"
MSG_ERROR     = "ERROR"


# ── Protocol Helpers ───────────────────────────────────────────────

def _build_protocol_msg(msg_type: str, payload: dict) -> bytes:
    """Build a framed protocol message."""
    message = {"type": msg_type, **payload}
    return frame_message(json.dumps(message).encode("utf-8"))


def _read_protocol_msg(sock) -> dict:
    """Read and parse a protocol message from socket."""
    data = read_framed_message(sock)
    if data is None:
        raise ConnectionError("Connection closed during key exchange")
    return json.loads(data.decode("utf-8"))


# ── DH Key Generation ─────────────────────────────────────────────

def _generate_dh_private():
    """Generate a random DH private exponent (256 bits)."""
    return secrets.randbelow(DH_PRIME - 2) + 1


def _compute_dh_public(private: int) -> int:
    """Compute the DH public value: g^private mod p."""
    return pow(DH_GENERATOR, private, DH_PRIME)


def _compute_shared_secret(peer_public: int, my_private: int) -> bytes:
    """Compute the DH shared secret: peer_public^my_private mod p."""
    shared_int = pow(peer_public, my_private, DH_PRIME)
    # Convert to bytes (256 bytes to cover 2048-bit value)
    return shared_int.to_bytes(256, byteorder="big")


# ── Initiator Side (Client / Alice) ───────────────────────────────

def initiator_key_exchange(sock, my_cert, my_private_key, ca_cert):
    """
    Execute the key exchange protocol as the initiator (Alice).
    Returns the derived AES-256 session key, or raises on failure.
    """
    print("[Protocol] Starting CertDH key exchange as INITIATOR...")

    # ── Step 1: Send HELLO with our certificate ──
    my_cert_pem = certificate_to_pem(my_cert).decode("utf-8")
    sock.sendall(_build_protocol_msg(MSG_HELLO, {"certificate": my_cert_pem}))
    print("[Protocol] Step 1: Sent HELLO with certificate")

    # ── Step 2: Receive HELLO_ACK with peer certificate ──
    msg = _read_protocol_msg(sock)
    if msg["type"] == MSG_ERROR:
        raise Exception(f"Peer error: {msg.get('reason', 'unknown')}")
    if msg["type"] != MSG_HELLO_ACK:
        raise Exception(f"Expected HELLO_ACK, got {msg['type']}")

    peer_cert = pem_to_certificate(msg["certificate"].encode("utf-8"))
    peer_cn = _get_cn(peer_cert)
    print(f"[Protocol] Step 2: Received HELLO_ACK from '{peer_cn}'")

    # ── Step 3: Verify peer certificate against CA ──
    if not verify_certificate_chain(peer_cert, ca_cert):
        sock.sendall(_build_protocol_msg(MSG_ERROR, {"reason": "Certificate verification failed"}))
        raise Exception("Peer certificate verification FAILED — not signed by trusted CA!")
    print("[Protocol] Step 3: Peer certificate VERIFIED against CA ✓")

    # ── Step 4: Generate DH parameters and send ──
    dh_private = _generate_dh_private()
    dh_public = _compute_dh_public(dh_private)

    # Sign the DH public value with our private key
    dh_public_bytes = dh_public.to_bytes(256, byteorder="big")
    dh_signature = sign_data(my_private_key, dh_public_bytes)

    sock.sendall(_build_protocol_msg(MSG_DH_PARAMS, {
        "p": hex(DH_PRIME),
        "g": DH_GENERATOR,
        "dh_public": hex(dh_public),
        "signature": dh_signature.hex(),
    }))
    print("[Protocol] Step 4: Sent DH public value (signed)")

    # ── Step 5: Receive DH reply ──
    msg = _read_protocol_msg(sock)
    if msg["type"] == MSG_ERROR:
        raise Exception(f"Peer error: {msg.get('reason', 'unknown')}")
    if msg["type"] != MSG_DH_REPLY:
        raise Exception(f"Expected DH_REPLY, got {msg['type']}")

    peer_dh_public = int(msg["dh_public"], 16)
    peer_dh_sig = bytes.fromhex(msg["signature"])

    # Verify peer's DH signature
    peer_dh_public_bytes = peer_dh_public.to_bytes(256, byteorder="big")
    if not verify_signature(peer_cert.public_key(), peer_dh_sig, peer_dh_public_bytes):
        raise Exception("Peer DH signature verification FAILED!")
    print("[Protocol] Step 5: Received and verified peer's DH value ✓")

    # ── Step 6: Compute shared secret ──
    shared_secret = _compute_shared_secret(peer_dh_public, dh_private)
    session_key = derive_session_key(shared_secret)
    print("[Protocol] Step 6: Shared secret computed, session key derived ✓")
    print("[Protocol] Key exchange COMPLETE — secure channel established!\n")

    return session_key, peer_cn


# ── Responder Side (Server / Bob) ──────────────────────────────────

def responder_key_exchange(sock, my_cert, my_private_key, ca_cert):
    """
    Execute the key exchange protocol as the responder (Bob).
    Returns the derived AES-256 session key, or raises on failure.
    """
    print("[Protocol] Starting CertDH key exchange as RESPONDER...")

    # ── Step 1: Receive HELLO with peer certificate ──
    msg = _read_protocol_msg(sock)
    if msg["type"] != MSG_HELLO:
        raise Exception(f"Expected HELLO, got {msg['type']}")

    peer_cert = pem_to_certificate(msg["certificate"].encode("utf-8"))
    peer_cn = _get_cn(peer_cert)
    print(f"[Protocol] Step 1: Received HELLO from '{peer_cn}'")

    # ── Step 2: Send HELLO_ACK with our certificate ──
    my_cert_pem = certificate_to_pem(my_cert).decode("utf-8")
    sock.sendall(_build_protocol_msg(MSG_HELLO_ACK, {"certificate": my_cert_pem}))
    print("[Protocol] Step 2: Sent HELLO_ACK with certificate")

    # ── Step 3: Verify peer certificate against CA ──
    if not verify_certificate_chain(peer_cert, ca_cert):
        sock.sendall(_build_protocol_msg(MSG_ERROR, {"reason": "Certificate verification failed"}))
        raise Exception("Peer certificate verification FAILED — not signed by trusted CA!")
    print("[Protocol] Step 3: Peer certificate VERIFIED against CA ✓")

    # ── Step 4: Receive DH parameters ──
    msg = _read_protocol_msg(sock)
    if msg["type"] == MSG_ERROR:
        raise Exception(f"Peer error: {msg.get('reason', 'unknown')}")
    if msg["type"] != MSG_DH_PARAMS:
        raise Exception(f"Expected DH_PARAMS, got {msg['type']}")

    peer_dh_public = int(msg["dh_public"], 16)
    peer_dh_sig = bytes.fromhex(msg["signature"])

    # Verify peer's DH signature
    peer_dh_public_bytes = peer_dh_public.to_bytes(256, byteorder="big")
    if not verify_signature(peer_cert.public_key(), peer_dh_sig, peer_dh_public_bytes):
        raise Exception("Peer DH signature verification FAILED!")
    print("[Protocol] Step 4: Received and verified peer's DH params ✓")

    # ── Step 5: Generate our DH value and send reply ──
    dh_private = _generate_dh_private()
    dh_public = _compute_dh_public(dh_private)

    dh_public_bytes = dh_public.to_bytes(256, byteorder="big")
    dh_signature = sign_data(my_private_key, dh_public_bytes)

    sock.sendall(_build_protocol_msg(MSG_DH_REPLY, {
        "dh_public": hex(dh_public),
        "signature": dh_signature.hex(),
    }))
    print("[Protocol] Step 5: Sent DH reply (signed)")

    # ── Step 6: Compute shared secret ──
    shared_secret = _compute_shared_secret(peer_dh_public, dh_private)
    session_key = derive_session_key(shared_secret)
    print("[Protocol] Step 6: Shared secret computed, session key derived ✓")
    print("[Protocol] Key exchange COMPLETE — secure channel established!\n")

    return session_key, peer_cn


# ── Utility ────────────────────────────────────────────────────────

def _get_cn(cert) -> str:
    """Extract the Common Name from a certificate."""
    from cryptography.x509.oid import NameOID
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else "Unknown"
