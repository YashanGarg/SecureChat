# SecureChat

Encrypted peer-to-peer chat using a **custom CertDH key exchange protocol** and **AES-256-GCM** message encryption. No TLS or any standard key exchange protocol is used — everything is built from scratch on raw TCP sockets.

Includes both a **CLI** and a **Tkinter GUI** frontend.

---

## GUI Preview
### Host
<img width="1920" height="1200" alt="gui_host1" src="https://github.com/user-attachments/assets/19880b78-1a22-47fe-b6e2-3ff9b1ca4706" />

<img width="1919" height="1169" alt="gui_host2" src="https://github.com/user-attachments/assets/88720f39-8eb9-4861-b539-0ffaadb0c4ba" />

### Joiner
<img width="1920" height="1200" alt="gui_joiner1" src="https://github.com/user-attachments/assets/6bd80b8a-e013-4f55-98bd-e9e2bfb58ef7" />

<img width="1909" height="1170" alt="gui_joiner2" src="https://github.com/user-attachments/assets/8633895c-8a87-44f2-957f-54c83f245088" />

---

## CLI Preview
### Host
<img width="1914" height="1132" alt="Host" src="https://github.com/user-attachments/assets/d2b725ae-5362-4eff-b41a-7235b3eadf75" />

### Joiner
<img width="1918" height="1151" alt="Joiner" src="https://github.com/user-attachments/assets/1ee60f9c-0690-4489-beec-a2798a92a3ca" />

---

## Quick Start

### Prerequisites

- Python 3.9+
- [cryptography](https://pypi.org/project/cryptography/) library

### Install

```bash
pip install -r requirements.txt
```

### Run

**GUI** (recommended):

```bash
python gui.py
```

**CLI**:

```bash
python cli.py
```

### Usage

1. **Host** — One person selects *Host*, picks a name and port, then starts the server.
2. **Join** — The other person selects *Join*, enters the host's IP and port, then connects.

Certificate enrollment is automatic: the joiner sends a CSR to the host, receives a signed certificate back, and the CertDH handshake runs on the same connection. No manual file copying is needed.

You can also pre-generate certificates with:

```bash
python setup_certs.py                      # creates CA + Alice + Bob
python setup_certs.py --add-user Charlie   # add a user to existing CA
python setup_certs.py --names Eve Mallory  # custom initial names
```

---

## Architecture
<img width="2816" height="1536" alt="image1" src="https://github.com/user-attachments/assets/9f3fc17f-1744-4506-868e-b88e3144f2d0" />

---

## CertDH Protocol

Combines **X.509 certificate authentication** with **Diffie-Hellman key exchange** to establish a shared secret over an untrusted network.

### Handshake

<img width="2816" height="1536" alt="image" src="https://github.com/user-attachments/assets/dcf06e96-fbbb-407c-b3fa-0b9c148852a0" />


### CSR-Based Enrollment (First Connection)

When a joiner connects, inline enrollment happens automatically before the handshake:

<img width="2816" height="1536" alt="image3" src="https://github.com/user-attachments/assets/b9616cf8-a04d-4d34-9f87-c877b9dc33b1" />


### Trust Chain

```
Root CA (self-signed)
 ├── Host's Certificate   (signed by Root CA)
 └── Joiner's Certificate (signed by Root CA, via CSR enrollment)
```

### Security Properties

| Property | Mechanism |
|---|---|
| **Authentication** | X.509 certificates verified against a shared CA |
| **Key Exchange** | Diffie-Hellman with signed public values (2048-bit MODP, RFC 3526 Group 14) |
| **Forward Secrecy** | Ephemeral DH keys — new keys per session |
| **Encryption** | AES-256-GCM (authenticated encryption) |
| **Key Derivation** | HKDF-SHA256 from raw DH shared secret |
| **Integrity** | GCM authentication tag on every message |
| **Replay Protection** | Random 12-byte nonce per message |

---

## Project Files

| File | Description |
|---|---|
| `gui.py` | Tkinter GUI frontend (Catppuccin Mocha theme) |
| `cli.py` | CLI frontend (interactive terminal with ANSI colors) |
| `protocol.py` | CertDH key exchange implementation |
| `crypto_utils.py` | AES-256-GCM, RSA signatures, certificate helpers, TCP framing |
| `setup_certs.py` | Certificate generation (Root CA + client certs, CSR signing) |
| `requirements.txt` | Python dependencies |
| `certs/` | Generated certificates and keys (created at runtime) |
| `setup_certs.py` | Root CA and client certificate generation |
| `requirements.txt` | Python dependencies |
| `certs/` | Generated certificates and keys (created at runtime) |

---

## Requirements

- **Python 3.10+**
- **cryptography** library (`pip install cryptography`)
- **Tkinter** (ships with Python on Windows/macOS; `sudo apt install python3-tk` on Linux)

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Launch

**GUI (recommended):**
```bash
python gui.py
```

**CLI:**
```bash
python setup.py
```

### 3. Usage

**Person A — Host:**
1. Enter your name
2. Select **Host (Server)**
3. Choose a port (default 5555)
4. Click **Start** — share the displayed IP with Person B

**Person B — Join:**
1. Enter your name
2. Select **Join (Client)**
3. Enter the host's IP and port
4. Click **Start** — certificate enrollment and key exchange happen automatically

Once connected, messages are end-to-end encrypted with AES-256-GCM. Type `/quit` to disconnect.

---

## How It Works

1. **Host** generates a Root CA and their own certificate, then listens on a TCP port
2. **Joiner** connects — if they have no certificate, they send a CSR and receive a signed certificate from the host's CA (inline enrollment)
3. Both parties run the **CertDH handshake**: exchange certificates, verify against the CA, perform signed Diffie-Hellman, and derive a shared AES-256 session key
4. All chat messages are encrypted with **AES-256-GCM** using a random nonce per message
5. Either party can disconnect at any time
