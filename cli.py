"""
SecureChat — Interactive Setup & Launch

Run this single script to set up and start chatting.
No manual certificate management or file transfers needed.

    python setup.py

Flow:
  Host  → Generates CA + your certificate, waits for peer to connect.
  Join  → Connects to host, auto-enrolls (gets a signed certificate
          from the host's CA over the wire), then starts chatting.

The enrollment protocol (CSR-based) runs on the same TCP connection,
right before the normal CertDH handshake, so only one port is needed.
"""

import os
import sys
import re
import json
import signal
import atexit
import socket
import struct
import threading
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_csr

from setup_certs import CERTS_DIR, create_root_ca, create_client_certificate
from crypto_utils import (
    load_certificate,
    load_private_key,
    encrypt_message,
    decrypt_message,
    frame_message,
    read_framed_message,
)
from protocol import initiator_key_exchange, responder_key_exchange


# ── ANSI colours ────────────────────────────────────────────────────

COLOR_RESET  = "\033[0m"
COLOR_GREEN  = "\033[92m"
COLOR_CYAN   = "\033[96m"
COLOR_YELLOW = "\033[93m"
COLOR_RED    = "\033[91m"
COLOR_BOLD   = "\033[1m"
COLOR_DIM    = "\033[2m"

# Global ref so cleanup can find the active user name
_active_user_name = None


# ── Socket wrapper (for replaying an already-read frame) ────────────

class _BufferedSocket:
    """Wrap a real socket, prepending *initial_bytes* to future reads."""

    def __init__(self, sock, initial_bytes=b""):
        self._sock = sock
        self._buf = initial_bytes

    def recv(self, n):
        if self._buf:
            chunk = self._buf[:n]
            self._buf = self._buf[n:]
            return chunk
        return self._sock.recv(n)

    def sendall(self, data):
        return self._sock.sendall(data)

    def close(self):
        return self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)


# ── Low-level helpers ───────────────────────────────────────────────

def _safe(name):
    """Sanitise a display name into a safe filename component."""
    return name.lower().replace(" ", "_")


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_raw_frame(sock):
    """Read one length-prefixed frame and return **all** raw bytes
    (4-byte header + payload) so they can be replayed later."""
    header = _recv_exact(sock, 4)
    if not header:
        return None
    length = struct.unpack("!I", header)[0]
    payload = _recv_exact(sock, length)
    if not payload:
        return None
    return header + payload


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


# ── Chat loop (reused by both host & join) ──────────────────────────

def _receive_loop(sock, key, peer, stop):
    while not stop.is_set():
        try:
            data = read_framed_message(sock)
            if data is None:
                print(f"\n{COLOR_RED}[!] Connection closed by {peer}.{COLOR_RESET}")
                stop.set()
                break
            text = decrypt_message(key, data)
            print(f"\r{COLOR_GREEN}[{_ts()}] {peer}: {text}{COLOR_RESET}")
            print(f"{COLOR_YELLOW}You > {COLOR_RESET}", end="", flush=True)
        except Exception as exc:
            if not stop.is_set():
                print(f"\n{COLOR_RED}[!] Receive error: {exc}{COLOR_RESET}")
                stop.set()
            break


def _send_loop(sock, key, me, stop):
    print(f"{COLOR_DIM}Type messages below. Ctrl+C, /quit or /close to exit.{COLOR_RESET}\n")
    while not stop.is_set():
        try:
            msg = input(f"{COLOR_YELLOW}You > {COLOR_RESET}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{COLOR_DIM}[*] Disconnecting...{COLOR_RESET}")
            stop.set()
            break
        if not msg.strip():
            continue
        if msg.strip().lower() in ("/quit", "/close"):
            print(f"{COLOR_DIM}[*] Disconnecting...{COLOR_RESET}")
            stop.set()
            break
        try:
            sock.sendall(frame_message(encrypt_message(key, msg)))
        except Exception as exc:
            print(f"{COLOR_RED}[!] Send failed: {exc}{COLOR_RESET}")
            stop.set()
            break


def _cleanup_certs(name=None):
    """Delete the user's certificate and key files."""
    target = name or _active_user_name
    if not target:
        return
    sn = _safe(target)
    for filename in (f"{sn}_cert.pem", f"{sn}_key.pem"):
        path = os.path.join(CERTS_DIR, filename)
        try:
            if os.path.exists(path):
                os.remove(path)
                print(f"  {COLOR_DIM}[*] Removed {filename}{COLOR_RESET}")
        except OSError:
            pass


def _run_chat(sock, session_key, my_name, peer_name):
    print(f"\n{COLOR_GREEN}{COLOR_BOLD}Secure channel with {peer_name} established!{COLOR_RESET}\n")
    stop = threading.Event()
    t = threading.Thread(target=_receive_loop,
                         args=(sock, session_key, peer_name, stop),
                         daemon=True)
    t.start()
    _send_loop(sock, session_key, my_name, stop)


# ── Interactive prompts ─────────────────────────────────────────────

def _banner():
    print(f"""
{COLOR_CYAN}{COLOR_BOLD}╔══════════════════════════════════════════════════════════╗
║              SecureChat — Interactive Setup               ║
║         Custom CertDH Key Exchange + AES-256-GCM          ║
╚══════════════════════════════════════════════════════════╝{COLOR_RESET}
""")


def _ask_name():
    while True:
        name = input(f"  {COLOR_YELLOW}Enter your name: {COLOR_RESET}").strip()
        if name and re.match(r"^[A-Za-z][A-Za-z0-9_ ]{0,29}$", name):
            return name
        print(f"  {COLOR_RED}Use letters, digits, spaces or underscores "
              f"(must start with a letter, max 30 chars).{COLOR_RESET}")


def _ask_role():
    print(f"\n  {COLOR_CYAN}1) Host a chat   (you are the server)")
    print(f"  2) Join a chat  (connect to someone else){COLOR_RESET}")
    while True:
        c = input(f"\n  {COLOR_YELLOW}Your choice [1/2]: {COLOR_RESET}").strip()
        if c in ("1", "2"):
            return "server" if c == "1" else "client"
        print(f"  {COLOR_RED}Please enter 1 or 2.{COLOR_RESET}")


def _ask_port():
    while True:
        raw = input(f"  {COLOR_YELLOW}Port [5555]: {COLOR_RESET}").strip()
        if not raw:
            return 5555
        try:
            p = int(raw)
            if 1024 <= p <= 65535:
                return p
        except ValueError:
            pass
        print(f"  {COLOR_RED}Enter a number between 1024 and 65535.{COLOR_RESET}")


def _ask_host():
    h = input(f"  {COLOR_YELLOW}Server IP address [127.0.0.1]: {COLOR_RESET}").strip()
    return h if h else "127.0.0.1"


# ── Certificate & enrollment helpers ────────────────────────────────

def _has_certs(name):
    sn = _safe(name)
    return all(
        os.path.exists(os.path.join(CERTS_DIR, f))
        for f in [f"{sn}_cert.pem", f"{sn}_key.pem", "ca_cert.pem"]
    )


def _ensure_ca():
    """Return (ca_key, ca_cert), generating them if necessary."""
    os.makedirs(CERTS_DIR, exist_ok=True)
    kp = os.path.join(CERTS_DIR, "ca_key.pem")
    cp = os.path.join(CERTS_DIR, "ca_cert.pem")
    if os.path.exists(kp) and os.path.exists(cp):
        print(f"  {COLOR_DIM}[*] Loading existing CA...{COLOR_RESET}")
        with open(kp, "rb") as f:
            ca_key = load_pem_private_key(f.read(), password=None)
        with open(cp, "rb") as f:
            ca_cert = load_pem_x509_certificate(f.read())
        return ca_key, ca_cert
    return create_root_ca()


def _ensure_user_cert(name, ca_key, ca_cert):
    sn = _safe(name)
    if (os.path.exists(os.path.join(CERTS_DIR, f"{sn}_cert.pem"))
            and os.path.exists(os.path.join(CERTS_DIR, f"{sn}_key.pem"))):
        print(f"  {COLOR_DIM}[*] Certificate for '{name}' already exists.{COLOR_RESET}")
        return
    create_client_certificate(name, ca_key, ca_cert)


def _make_csr(private_key, name):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SecureState"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]))
        .sign(private_key, hashes.SHA256())
    )


def _sign_csr(csr, ca_key, ca_cert):
    """Sign a CSR with the CA → returns a client x509 certificate."""
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


# ── Host (server) flow ──────────────────────────────────────────────

def _host(name, port):
    # ---- certificates ----
    ca_key, ca_cert = _ensure_ca()
    _ensure_user_cert(name, ca_key, ca_cert)

    sn = _safe(name)
    my_cert = load_certificate(os.path.join(CERTS_DIR, f"{sn}_cert.pem"))
    my_key  = load_private_key(os.path.join(CERTS_DIR, f"{sn}_key.pem"))

    # ---- listen ----
    local_ip = _get_local_ip()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)

    print(f"\n  {COLOR_CYAN}[*] {name}'s server listening on port {port}{COLOR_RESET}")
    print(f"  {COLOR_GREEN}[*] Your IP: {local_ip}{COLOR_RESET}")
    print(f"\n  {COLOR_YELLOW}Tell the other person to run:{COLOR_RESET}")
    print(f"      python setup.py")
    print(f"  {COLOR_YELLOW}and connect to {COLOR_GREEN}{local_ip}:{port}{COLOR_RESET}")
    print(f"\n  {COLOR_DIM}Waiting for peer to connect...{COLOR_RESET}\n")

    conn, addr = srv.accept()
    print(f"  {COLOR_GREEN}[+] Connection from {addr[0]}:{addr[1]}{COLOR_RESET}")

    try:
        # ---- peek at first frame ----
        raw = _read_raw_frame(conn)
        if raw is None:
            print(f"  {COLOR_RED}[!] Peer disconnected immediately.{COLOR_RESET}")
            return

        first = json.loads(raw[4:].decode("utf-8"))

        if first.get("type") == "ENROLL_REQUEST":
            # ── inline enrollment ──
            peer = first["name"]
            print(f"  {COLOR_CYAN}[*] Enrollment request from '{peer}'{COLOR_RESET}")

            csr = load_pem_x509_csr(first["csr"].encode("utf-8"))
            if not csr.is_signature_valid:
                print(f"  {COLOR_RED}[!] Invalid CSR signature — rejecting.{COLOR_RESET}")
                return

            signed = _sign_csr(csr, ca_key, ca_cert)
            resp = json.dumps({
                "type": "ENROLL_RESPONSE",
                "certificate": signed.public_bytes(serialization.Encoding.PEM).decode(),
                "ca_certificate": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
            })
            conn.sendall(frame_message(resp.encode("utf-8")))
            print(f"  {COLOR_GREEN}[+] Certificate issued for '{peer}'{COLOR_RESET}\n")

            # CertDH follows on the SAME connection
            session_key, peer_cn = responder_key_exchange(
                conn, my_cert, my_key, ca_cert)

        else:
            # Peer already enrolled — replay the frame so responder_key_exchange
            # can read the HELLO it expects.
            wrapped = _BufferedSocket(conn, raw)
            session_key, peer_cn = responder_key_exchange(
                wrapped, my_cert, my_key, ca_cert)

        # ---- chat ----
        _run_chat(conn, session_key, name, peer_cn)

    except Exception as exc:
        print(f"  {COLOR_RED}[!] Error: {exc}{COLOR_RESET}")
    finally:
        conn.close()
        srv.close()
        _cleanup_certs(name)
        print(f"  {COLOR_DIM}[*] Connection closed.{COLOR_RESET}")


# ── Join (client) flow ──────────────────────────────────────────────

def _join(name, host, port):
    os.makedirs(CERTS_DIR, exist_ok=True)
    sn = _safe(name)

    print(f"\n  {COLOR_CYAN}[*] Connecting to {host}:{port}...{COLOR_RESET}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        print(f"  {COLOR_RED}[!] Connection refused — is the host running?{COLOR_RESET}")
        sys.exit(1)
    print(f"  {COLOR_GREEN}[+] Connected!{COLOR_RESET}")

    try:
        # ---- Always enroll with the host to get a certificate signed ----
        # ---- by the host's CA.  Locally-generated certs use a        ----
        # ---- different CA and will fail verification across machines. ----
        print(f"  {COLOR_CYAN}[*] Enrolling with host...{COLOR_RESET}")

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path = os.path.join(CERTS_DIR, f"{sn}_key.pem")
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        csr = _make_csr(key, name)
        req = json.dumps({
            "type": "ENROLL_REQUEST",
            "name": name,
            "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
        })
        sock.sendall(frame_message(req.encode("utf-8")))

        resp_raw = read_framed_message(sock)
        if resp_raw is None:
            print(f"  {COLOR_RED}[!] Server closed connection during enrollment.{COLOR_RESET}")
            sys.exit(1)

        resp = json.loads(resp_raw.decode("utf-8"))
        if resp.get("type") != "ENROLL_RESPONSE":
            print(f"  {COLOR_RED}[!] Unexpected server response: "
                  f"{resp.get('type')}{COLOR_RESET}")
            sys.exit(1)

        with open(os.path.join(CERTS_DIR, f"{sn}_cert.pem"), "wb") as f:
            f.write(resp["certificate"].encode())
        with open(os.path.join(CERTS_DIR, "ca_cert.pem"), "wb") as f:
            f.write(resp["ca_certificate"].encode())

        print(f"  {COLOR_GREEN}[+] Enrolled! Certificate saved.{COLOR_RESET}\n")

        # ---- key exchange ----
        my_cert = load_certificate(os.path.join(CERTS_DIR, f"{sn}_cert.pem"))
        my_key  = load_private_key(os.path.join(CERTS_DIR, f"{sn}_key.pem"))
        ca_cert = load_certificate(os.path.join(CERTS_DIR, "ca_cert.pem"))

        session_key, peer_cn = initiator_key_exchange(
            sock, my_cert, my_key, ca_cert)

        # ---- chat ----
        _run_chat(sock, session_key, name, peer_cn)

    except Exception as exc:
        print(f"  {COLOR_RED}[!] Error: {exc}{COLOR_RESET}")
    finally:
        sock.close()
        _cleanup_certs(name)
        print(f"  {COLOR_DIM}[*] Connection closed.{COLOR_RESET}")


# ── Entry point ─────────────────────────────────────────────────────

def main():
    global _active_user_name
    _banner()

    name = _ask_name()
    _active_user_name = name

    # Register cleanup for unexpected termination (terminal closed, kill, etc.)
    atexit.register(_cleanup_certs)
    signal.signal(signal.SIGINT, lambda *_: (atexit.unregister(_cleanup_certs), _cleanup_certs(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *_: (atexit.unregister(_cleanup_certs), _cleanup_certs(), sys.exit(0)))

    role = _ask_role()

    if role == "server":
        port = _ask_port()
        _host(name, port)
    else:
        host = _ask_host()
        port = _ask_port()
        _join(name, host, port)


if __name__ == "__main__":
    main()
