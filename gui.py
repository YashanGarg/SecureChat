"""
SecureChat — Tkinter GUI Frontend

A graphical interface for the SecureChat encrypted chat application.
Reuses the same CertDH protocol, crypto utilities, and certificate logic
from the CLI version.

    python gui.py
"""

import os
import re
import json
import socket
import struct
import threading
import datetime
import tkinter as tk
from tkinter import messagebox

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_csr

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


# ── Helpers (reused from setup.py) ──────────────────────────────────

def _safe(name):
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
    header = _recv_exact(sock, 4)
    if not header:
        return None
    length = struct.unpack("!I", header)[0]
    payload = _recv_exact(sock, length)
    if not payload:
        return None
    return header + payload


def _has_certs(name):
    sn = _safe(name)
    return all(
        os.path.exists(os.path.join(CERTS_DIR, f))
        for f in [f"{sn}_cert.pem", f"{sn}_key.pem", "ca_cert.pem"]
    )


class _BufferedSocket:
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


# ── Certificate helpers ─────────────────────────────────────────────

def _ensure_ca():
    os.makedirs(CERTS_DIR, exist_ok=True)
    kp = os.path.join(CERTS_DIR, "ca_key.pem")
    cp = os.path.join(CERTS_DIR, "ca_cert.pem")
    if os.path.exists(kp) and os.path.exists(cp):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.x509 import load_pem_x509_certificate
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
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
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


# ── Color scheme (Catppuccin Mocha-inspired) ────────────────────────

BG_BASE      = "#1e1e2e"
BG_MANTLE    = "#181825"
BG_CRUST     = "#11111b"
BG_SURFACE0  = "#313244"
BG_SURFACE1  = "#45475a"
BG_SURFACE2  = "#585b70"
FG_TEXT      = "#cdd6f4"
FG_SUBTEXT1  = "#bac2de"
FG_SUBTEXT0  = "#a6adc8"
FG_OVERLAY0  = "#6c7086"
FG_BLUE      = "#89b4fa"
FG_SAPPHIRE  = "#74c7ec"
FG_GREEN     = "#a6e3a1"
FG_YELLOW    = "#f9e2af"
FG_RED       = "#f38ba8"
FG_MAUVE     = "#cba6f7"
FG_LAVENDER  = "#b4befe"
FG_TEAL      = "#94e2d5"

BUBBLE_ME    = "#313244"
BUBBLE_PEER  = "#1e293b"
BTN_BG       = "#89b4fa"
BTN_BG_HOVER = "#74c7ec"
BTN_FG       = "#1e1e2e"

FONT_FAMILY  = "Segoe UI"
FONT_MONO    = "Cascadia Code"


# ── Rounded rectangle helper ───────────────────────────────────────

def _round_rect(canvas, x1, y1, x2, y2, r=12, **kwargs):
    """Draw a rounded rectangle on a canvas."""
    points = [
        x1 + r, y1, x2 - r, y1,
        x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2,
        x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r,
        x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


# ── Custom widgets ──────────────────────────────────────────────────

class RoundedEntry(tk.Canvas):
    """A text entry with a rounded background."""

    def __init__(self, parent, width=280, height=38, radius=10, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=parent["bg"], highlightthickness=0, bd=0)
        self._radius = radius
        self._bg_color = BG_SURFACE0
        self._rect = _round_rect(self, 0, 0, width, height, r=radius,
                                  fill=self._bg_color, outline="")

        self.entry = tk.Entry(self, font=(FONT_FAMILY, 11), bg=self._bg_color,
                              fg=FG_TEXT, insertbackground=FG_TEXT,
                              relief="flat", bd=0,
                              highlightthickness=0)
        self.create_window(14, height // 2, window=self.entry,
                           anchor="w", width=width - 28)

        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", self._on_focus_out)
        if "placeholder" in kwargs:
            self._placeholder = kwargs["placeholder"]
            self._show_placeholder()
        else:
            self._placeholder = None

    def _on_focus_in(self, _e=None):
        self.itemconfigure(self._rect, outline=FG_BLUE, width=1.5)
        if self._placeholder and self.entry.get() == self._placeholder:
            self.entry.delete(0, "end")
            self.entry.configure(fg=FG_TEXT)

    def _on_focus_out(self, _e=None):
        self.itemconfigure(self._rect, outline="", width=0)
        if self._placeholder and not self.entry.get():
            self._show_placeholder()

    def _show_placeholder(self):
        self.entry.delete(0, "end")
        self.entry.insert(0, self._placeholder)
        self.entry.configure(fg=FG_OVERLAY0)

    def get(self):
        val = self.entry.get()
        if self._placeholder and val == self._placeholder:
            return ""
        return val

    def insert(self, index, text):
        self.entry.configure(fg=FG_TEXT)
        self.entry.insert(index, text)

    def delete(self, start, end):
        self.entry.delete(start, end)

    def focus_set(self):
        self.entry.focus_set()

    def bind_entry(self, event, callback):
        self.entry.bind(event, callback)


class RoundedButton(tk.Canvas):
    """A button with rounded background and hover animation."""

    def __init__(self, parent, text="", width=180, height=40, radius=10,
                 bg_color=BTN_BG, hover_color=BTN_BG_HOVER, fg_color=BTN_FG,
                 command=None, font_size=11):
        super().__init__(parent, width=width, height=height,
                         bg=parent["bg"], highlightthickness=0, bd=0)
        self._bg = bg_color
        self._hover = hover_color
        self._command = command
        self._enabled = True

        self._rect = _round_rect(self, 0, 0, width, height, r=radius,
                                  fill=bg_color, outline="")
        self._text = self.create_text(width // 2, height // 2, text=text,
                                       fill=fg_color,
                                       font=(FONT_FAMILY, font_size, "bold"))

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.configure(cursor="hand2")

    def _on_enter(self, _e=None):
        if self._enabled:
            self.itemconfigure(self._rect, fill=self._hover)

    def _on_leave(self, _e=None):
        if self._enabled:
            self.itemconfigure(self._rect, fill=self._bg)

    def _on_click(self, _e=None):
        if self._enabled and self._command:
            self._command()

    def set_enabled(self, enabled):
        self._enabled = enabled
        if not enabled:
            self.itemconfigure(self._rect, fill=BG_SURFACE2)
            self.configure(cursor="arrow")
        else:
            self.itemconfigure(self._rect, fill=self._bg)
            self.configure(cursor="hand2")


class ToggleButton(tk.Canvas):
    """A segmented toggle for host/join selection."""

    def __init__(self, parent, options, width=300, height=38, radius=10,
                 command=None):
        super().__init__(parent, width=width, height=height,
                         bg=parent["bg"], highlightthickness=0, bd=0)
        self._items = options
        self._width = width
        self._height = height
        self._radius = radius
        self._command = command
        self._selected = 0

        # Background pill
        _round_rect(self, 0, 0, width, height, r=radius,
                     fill=BG_SURFACE0, outline="")

        self._seg_w = width // len(options)
        self._indicator = _round_rect(
            self, 2, 2, self._seg_w - 2, height - 2, r=radius - 2,
            fill=FG_BLUE, outline="")

        self._labels = []
        for i, (text, _val) in enumerate(options):
            cx = self._seg_w * i + self._seg_w // 2
            tid = self.create_text(cx, height // 2, text=text,
                                    font=(FONT_FAMILY, 10, "bold"),
                                    fill=BTN_FG if i == 0 else FG_OVERLAY0)
            self._labels.append(tid)

        self.bind("<Button-1>", self._on_click)
        self.configure(cursor="hand2")

    def _on_click(self, event):
        idx = min(event.x // self._seg_w, len(self._items) - 1)
        if idx == self._selected:
            return
        self._selected = idx

        # Move indicator
        x1 = self._seg_w * idx + 2
        x2 = self._seg_w * (idx + 1) - 2
        self.coords(self._indicator,
                     *self._pill_coords(x1, 2, x2, self._height - 2, self._radius - 2))

        for i, tid in enumerate(self._labels):
            self.itemconfigure(tid, fill=BTN_FG if i == idx else FG_OVERLAY0)

        if self._command:
            self._command(self._items[idx][1])

    def _pill_coords(self, x1, y1, x2, y2, r):
        return [
            x1 + r, y1, x2 - r, y1,
            x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2,
            x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r,
            x1, y1 + r, x1, y1,
        ]

    def get(self):
        return self._items[self._selected][1]


# ── Main Application ────────────────────────────────────────────────

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureChat")
        self.root.geometry("650x560")
        self.root.configure(bg=BG_BASE)
        self.root.minsize(520, 460)

        self.session_key = None
        self.sock = None
        self.server_sock = None
        self.peer_name = ""
        self.my_name = ""
        self.stop_event = threading.Event()

        self._build_setup_screen()

    # ── Setup Screen ────────────────────────────────────────────────

    def _build_setup_screen(self):
        self._clear()

        # Outer container
        outer = tk.Frame(self.root, bg=BG_BASE)
        outer.place(relx=0.5, rely=0.5, anchor="center")

        # Logo / title area
        tk.Label(outer, text="\U0001F512", font=(FONT_FAMILY, 30),
                 fg=FG_BLUE, bg=BG_BASE).pack(pady=(0, 4))
        tk.Label(outer, text="SecureChat", font=(FONT_FAMILY, 26, "bold"),
                 fg=FG_TEXT, bg=BG_BASE).pack(pady=(0, 2))
        tk.Label(outer, text="End-to-end encrypted  \u2022  CertDH  \u2022  AES-256-GCM",
                 font=(FONT_FAMILY, 9), fg=FG_OVERLAY0, bg=BG_BASE).pack(pady=(0, 24))

        # Card
        card = tk.Frame(outer, bg=BG_MANTLE, padx=32, pady=28)
        card.pack()

        # Name field
        tk.Label(card, text="YOUR NAME", font=(FONT_FAMILY, 8, "bold"),
                 fg=FG_OVERLAY0, bg=BG_MANTLE, anchor="w").pack(fill="x", pady=(0, 4))
        self.name_entry = RoundedEntry(card, width=300, placeholder="Enter your name")
        self.name_entry.pack(pady=(0, 16))

        # Role toggle
        tk.Label(card, text="MODE", font=(FONT_FAMILY, 8, "bold"),
                 fg=FG_OVERLAY0, bg=BG_MANTLE, anchor="w").pack(fill="x", pady=(0, 4))
        self.role_toggle = ToggleButton(
            card,
            options=[("\U0001F4E1  Host", "server"), ("\U0001F517  Join", "client")],
            width=300, height=38,
            command=self._on_role_change,
        )
        self.role_toggle.pack(pady=(0, 16))

        # Host IP field (hidden by default)
        self.host_wrapper = tk.Frame(card, bg=BG_MANTLE)
        tk.Label(self.host_wrapper, text="SERVER IP", font=(FONT_FAMILY, 8, "bold"),
                 fg=FG_OVERLAY0, bg=BG_MANTLE, anchor="w").pack(fill="x", pady=(0, 4))
        self.host_entry = RoundedEntry(self.host_wrapper, width=300,
                                       placeholder="e.g. 192.168.1.10")
        self.host_entry.pack(pady=(0, 16))

        # Port field
        tk.Label(card, text="PORT", font=(FONT_FAMILY, 8, "bold"),
                 fg=FG_OVERLAY0, bg=BG_MANTLE, anchor="w").pack(fill="x", pady=(0, 4))
        self.port_entry = RoundedEntry(card, width=300, placeholder="5555")
        self.port_entry.pack(pady=(0, 20))

        # Start button
        self.start_btn = RoundedButton(card, text="\U0001F680  Start Chat",
                                       width=300, height=42, radius=12,
                                       command=self._on_start)
        self.start_btn.pack()

        # Status label
        self.status_label = tk.Label(card, text="", font=(FONT_FAMILY, 9),
                                     fg=FG_OVERLAY0, bg=BG_MANTLE, wraplength=280)
        self.status_label.pack(pady=(12, 0))

        self._role = "server"

    def _on_role_change(self, role):
        self._role = role
        if role == "client":
            self.host_wrapper.pack(fill="x",
                                   before=self.port_entry.master.winfo_children()[-3])
        else:
            self.host_wrapper.pack_forget()

    def _on_start(self):
        name = self.name_entry.get().strip()
        if not name or not re.match(r"^[A-Za-z][A-Za-z0-9_ ]{0,29}$", name):
            messagebox.showerror("Invalid Name",
                                 "Use letters, digits, spaces or underscores\n"
                                 "(start with a letter, max 30 chars).")
            return

        port_str = self.port_entry.get().strip() or "5555"
        try:
            port = int(port_str)
            if not (1024 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Port", "Enter a number between 1024 and 65535.")
            return

        self.my_name = name
        self.start_btn.set_enabled(False)

        if self._role == "server":
            self._set_status("\u23f3  Generating certificates & waiting for peer...", FG_YELLOW)
            threading.Thread(target=self._host_thread, args=(name, port),
                             daemon=True).start()
        else:
            host = self.host_entry.get().strip() or "127.0.0.1"
            self._set_status(f"\u23f3  Connecting to {host}:{port}...", FG_YELLOW)
            threading.Thread(target=self._join_thread, args=(name, host, port),
                             daemon=True).start()

    # ── Chat Screen ─────────────────────────────────────────────────

    def _build_chat_screen(self):
        self._clear()

        # Header bar
        header = tk.Frame(self.root, bg=BG_MANTLE, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)

        left_hdr = tk.Frame(header, bg=BG_MANTLE)
        left_hdr.pack(side="left", padx=16, pady=8)

        # Peer avatar circle
        avatar = tk.Canvas(left_hdr, width=34, height=34,
                           bg=BG_MANTLE, highlightthickness=0)
        avatar.pack(side="left", padx=(0, 10))
        avatar.create_oval(1, 1, 33, 33, fill=FG_MAUVE, outline="")
        initial = self.peer_name[0].upper() if self.peer_name else "?"
        avatar.create_text(17, 17, text=initial,
                           font=(FONT_FAMILY, 13, "bold"), fill=BG_BASE)

        name_frame = tk.Frame(left_hdr, bg=BG_MANTLE)
        name_frame.pack(side="left")
        tk.Label(name_frame, text=self.peer_name,
                 font=(FONT_FAMILY, 12, "bold"), fg=FG_TEXT,
                 bg=BG_MANTLE).pack(anchor="w")
        tk.Label(name_frame, text="\u2022 Online  \u2022  Encrypted",
                 font=(FONT_FAMILY, 8), fg=FG_GREEN,
                 bg=BG_MANTLE).pack(anchor="w")

        # Right side of header: badge + close button
        right_hdr = tk.Frame(header, bg=BG_MANTLE)
        right_hdr.pack(side="right", padx=16)

        # Encryption badge
        badge_canvas = tk.Canvas(right_hdr, width=90, height=26,
                                 bg=BG_MANTLE, highlightthickness=0)
        badge_canvas.pack(side="left", padx=(0, 10))
        _round_rect(badge_canvas, 0, 0, 90, 26, r=8,
                     fill=BG_SURFACE0, outline="")
        badge_canvas.create_text(45, 13, text="\U0001F512 AES-256",
                                  font=(FONT_FAMILY, 8, "bold"), fill=FG_GREEN)

        # Close chat button
        self.close_btn = RoundedButton(
            right_hdr, text="\u2716  Close", width=80, height=26, radius=8,
            bg_color=FG_RED, hover_color="#e06080", fg_color=BG_BASE,
            command=self._on_close_chat, font_size=9)
        self.close_btn.pack(side="left")

        # Separator line
        sep = tk.Frame(self.root, bg=BG_SURFACE0, height=1)
        sep.pack(fill="x")

        # Message area (canvas-based for bubble rendering)
        msg_outer = tk.Frame(self.root, bg=BG_BASE)
        msg_outer.pack(fill="both", expand=True)

        self._msg_canvas = tk.Canvas(msg_outer, bg=BG_BASE, highlightthickness=0,
                                     bd=0)
        scrollbar = tk.Scrollbar(msg_outer, orient="vertical",
                                 command=self._msg_canvas.yview,
                                 bg=BG_SURFACE0, troughcolor=BG_BASE,
                                 width=8, relief="flat")
        self._msg_canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self._msg_canvas.pack(side="left", fill="both", expand=True)

        self._msg_frame = tk.Frame(self._msg_canvas, bg=BG_BASE)
        self._msg_window = self._msg_canvas.create_window(
            (0, 0), window=self._msg_frame, anchor="nw")

        self._msg_frame.bind("<Configure>", self._on_msg_frame_configure)
        self._msg_canvas.bind("<Configure>", self._on_canvas_configure)
        # Mouse-wheel scrolling
        self._msg_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Separator
        sep2 = tk.Frame(self.root, bg=BG_SURFACE0, height=1)
        sep2.pack(fill="x")

        # Input bar
        input_bar = tk.Frame(self.root, bg=BG_MANTLE, height=60)
        input_bar.pack(fill="x")
        input_bar.pack_propagate(False)

        input_inner = tk.Frame(input_bar, bg=BG_MANTLE)
        input_inner.pack(fill="x", padx=12, pady=10)

        # Entry with rounded bg
        entry_canvas = tk.Canvas(input_inner, height=38,
                                 bg=BG_MANTLE, highlightthickness=0, bd=0)
        entry_canvas.pack(side="left", fill="x", expand=True, padx=(0, 8))

        def _draw_entry_bg(event=None):
            entry_canvas.delete("bg")
            w = entry_canvas.winfo_width()
            _round_rect(entry_canvas, 0, 0, w, 38, r=10,
                        fill=BG_SURFACE0, outline="", tags="bg")
            entry_canvas.tag_lower("bg")

        entry_canvas.bind("<Configure>", _draw_entry_bg)

        self.msg_entry = tk.Entry(entry_canvas, font=(FONT_FAMILY, 11),
                                  bg=BG_SURFACE0, fg=FG_TEXT,
                                  insertbackground=FG_TEXT,
                                  relief="flat", bd=0, highlightthickness=0)
        entry_canvas.create_window(14, 19, window=self.msg_entry,
                                   anchor="w", width=400)
        self.msg_entry.bind("<Return>", self._on_send)
        self.msg_entry.focus_set()

        self.send_btn = RoundedButton(input_inner, text="Send \u27A4",
                                      width=80, height=38, radius=10,
                                      command=self._on_send, font_size=10)
        self.send_btn.pack(side="right")

        self._append_system("\U0001F512  Secure channel established")

    def _on_msg_frame_configure(self, _e=None):
        self._msg_canvas.configure(scrollregion=self._msg_canvas.bbox("all"))
        self._msg_canvas.yview_moveto(1.0)

    def _on_canvas_configure(self, event):
        self._msg_canvas.itemconfigure(self._msg_window, width=event.width)

    def _on_mousewheel(self, event):
        self._msg_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _append_bubble(self, sender, text, is_me):
        """Add a chat bubble to the message area."""
        row = tk.Frame(self._msg_frame, bg=BG_BASE)
        row.pack(fill="x", padx=16, pady=3)

        anchor = "e" if is_me else "w"
        bubble_bg = BUBBLE_ME if is_me else BUBBLE_PEER
        name_color = FG_YELLOW if is_me else FG_MAUVE

        bubble = tk.Frame(row, bg=bubble_bg, padx=14, pady=8)
        bubble.pack(anchor=anchor, padx=(60 if is_me else 0, 0 if is_me else 60))

        # Sender + timestamp on one line
        meta = tk.Frame(bubble, bg=bubble_bg)
        meta.pack(fill="x", anchor="w")

        tk.Label(meta, text=sender, font=(FONT_FAMILY, 9, "bold"),
                 fg=name_color, bg=bubble_bg).pack(side="left")

        ts = datetime.datetime.now().strftime("%H:%M")
        tk.Label(meta, text=ts, font=(FONT_FAMILY, 8),
                 fg=FG_OVERLAY0, bg=bubble_bg).pack(side="right", padx=(12, 0))

        # Message text
        msg_label = tk.Label(bubble, text=text, font=(FONT_FAMILY, 10),
                             fg=FG_TEXT, bg=bubble_bg, wraplength=340,
                             justify="left", anchor="w")
        msg_label.pack(fill="x", anchor="w", pady=(2, 0))

        self._msg_canvas.update_idletasks()
        self._msg_canvas.configure(scrollregion=self._msg_canvas.bbox("all"))
        self._msg_canvas.yview_moveto(1.0)

    def _append_system(self, text):
        """Add a centered system message."""
        row = tk.Frame(self._msg_frame, bg=BG_BASE)
        row.pack(fill="x", padx=16, pady=8)

        tk.Label(row, text=text, font=(FONT_FAMILY, 9),
                 fg=FG_OVERLAY0, bg=BG_BASE).pack(anchor="center")

        self._msg_canvas.update_idletasks()
        self._msg_canvas.configure(scrollregion=self._msg_canvas.bbox("all"))
        self._msg_canvas.yview_moveto(1.0)

    def _on_send(self, event=None):
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        self.msg_entry.delete(0, "end")

        if msg.lower() == "/quit":
            self._disconnect()
            return

        try:
            self.sock.sendall(frame_message(encrypt_message(self.session_key, msg)))
            self._append_bubble("You", msg, is_me=True)
        except Exception as exc:
            self._append_system(f"\u274c  Send failed: {exc}")
            self._disconnect()

    def _cleanup_certs(self):
        """Delete the current user's certificate and key files."""
        if not self.my_name:
            return
        sn = _safe(self.my_name)
        for filename in (f"{sn}_cert.pem", f"{sn}_key.pem"):
            path = os.path.join(CERTS_DIR, filename)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

    def _disconnect(self):
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        try:
            if self.server_sock:
                self.server_sock.close()
        except Exception:
            pass
        self._cleanup_certs()
        self._append_system("\U0001F534  Disconnected.")

    def _on_close_chat(self):
        """Handler for the Close button — disconnect and return to setup."""
        self._disconnect()
        self.session_key = None
        self.sock = None
        self.server_sock = None
        self.peer_name = ""
        self.my_name = ""
        self.stop_event = threading.Event()
        self._build_setup_screen()

    # ── Receive loop ────────────────────────────────────────────────

    def _receive_loop(self):
        while not self.stop_event.is_set():
            try:
                data = read_framed_message(self.sock)
                if data is None:
                    self._cleanup_certs()
                    self.root.after(0, self._append_system,
                                    f"\U0001F534  Connection closed by {self.peer_name}.")
                    self.stop_event.set()
                    break
                text = decrypt_message(self.session_key, data)
                self.root.after(0, self._append_bubble,
                                self.peer_name, text, False)
            except Exception as exc:
                if not self.stop_event.is_set():
                    self.root.after(0, self._append_system,
                                    f"Receive error: {exc}")
                    self.stop_event.set()
                break

    # ── Host thread ─────────────────────────────────────────────────

    def _host_thread(self, name, port):
        try:
            ca_key, ca_cert = _ensure_ca()
            _ensure_user_cert(name, ca_key, ca_cert)

            sn = _safe(name)
            my_cert = load_certificate(os.path.join(CERTS_DIR, f"{sn}_cert.pem"))
            my_key = load_private_key(os.path.join(CERTS_DIR, f"{sn}_key.pem"))

            local_ip = _get_local_ip()
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            self.server_sock = srv

            self.root.after(0, self._set_status,
                            f"Listening on {local_ip}:{port} — waiting for peer...",
                            FG_GREEN)

            conn, addr = srv.accept()
            self.sock = conn

            self.root.after(0, self._set_status,
                            f"Connection from {addr[0]}:{addr[1]} — handshaking...",
                            FG_YELLOW)

            # Peek first frame
            raw = _read_raw_frame(conn)
            if raw is None:
                self.root.after(0, self._set_status, "Peer disconnected.", FG_RED)
                return

            first = json.loads(raw[4:].decode("utf-8"))

            if first.get("type") == "ENROLL_REQUEST":
                peer = first["name"]
                self.root.after(0, self._set_status,
                                f"Enrolling '{peer}'...", FG_YELLOW)

                csr = load_pem_x509_csr(first["csr"].encode("utf-8"))
                if not csr.is_signature_valid:
                    self.root.after(0, self._set_status,
                                    "Invalid CSR — rejected.", FG_RED)
                    return

                signed = _sign_csr(csr, ca_key, ca_cert)
                resp = json.dumps({
                    "type": "ENROLL_RESPONSE",
                    "certificate": signed.public_bytes(serialization.Encoding.PEM).decode(),
                    "ca_certificate": ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
                })
                conn.sendall(frame_message(resp.encode("utf-8")))

                session_key, peer_cn = responder_key_exchange(
                    conn, my_cert, my_key, ca_cert)
            else:
                wrapped = _BufferedSocket(conn, raw)
                session_key, peer_cn = responder_key_exchange(
                    wrapped, my_cert, my_key, ca_cert)

            self.session_key = session_key
            self.peer_name = peer_cn

            self.root.after(0, self._enter_chat)

        except Exception as exc:
            self.root.after(0, self._set_status, f"Error: {exc}", FG_RED)
            self.root.after(0, lambda: self.start_btn.set_enabled(True))

    # ── Join thread ─────────────────────────────────────────────────

    def _join_thread(self, name, host, port):
        try:
            os.makedirs(CERTS_DIR, exist_ok=True)
            sn = _safe(name)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            self.sock = sock

            self.root.after(0, self._set_status, "Connected — checking certificates...",
                            FG_YELLOW)

            # Always enroll with the host to get a certificate signed by the
            # host's CA.  Locally-generated certs use a different CA and will
            # fail verification when the two machines are different.
            self.root.after(0, self._set_status, "Enrolling with host...",
                            FG_YELLOW)

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
                self.root.after(0, self._set_status,
                                "Server closed during enrollment.", FG_RED)
                return

            resp = json.loads(resp_raw.decode("utf-8"))
            if resp.get("type") != "ENROLL_RESPONSE":
                self.root.after(0, self._set_status,
                                f"Unexpected response: {resp.get('type')}", FG_RED)
                return

            with open(os.path.join(CERTS_DIR, f"{sn}_cert.pem"), "wb") as f:
                f.write(resp["certificate"].encode())
            with open(os.path.join(CERTS_DIR, "ca_cert.pem"), "wb") as f:
                f.write(resp["ca_certificate"].encode())

            self.root.after(0, self._set_status, "Enrolled! Running key exchange...",
                            FG_GREEN)

            my_cert = load_certificate(os.path.join(CERTS_DIR, f"{sn}_cert.pem"))
            my_key = load_private_key(os.path.join(CERTS_DIR, f"{sn}_key.pem"))
            ca_cert = load_certificate(os.path.join(CERTS_DIR, "ca_cert.pem"))

            session_key, peer_cn = initiator_key_exchange(
                sock, my_cert, my_key, ca_cert)

            self.session_key = session_key
            self.peer_name = peer_cn

            self.root.after(0, self._enter_chat)

        except ConnectionRefusedError:
            self.root.after(0, self._set_status,
                            "Connection refused — is the host running?", FG_RED)
            self.root.after(0, lambda: self.start_btn.set_enabled(True))
        except Exception as exc:
            self.root.after(0, self._set_status, f"Error: {exc}", FG_RED)
            self.root.after(0, lambda: self.start_btn.set_enabled(True))

    # ── Transition to chat ──────────────────────────────────────────

    def _enter_chat(self):
        self._build_chat_screen()
        threading.Thread(target=self._receive_loop, daemon=True).start()

    # ── Utilities ───────────────────────────────────────────────────

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _set_status(self, text, color=FG_OVERLAY0):
        try:
            self.status_label.configure(text=text, fg=color)
        except Exception:
            pass


# ── Entry point ─────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = SecureChatApp(root)
    root._app = app
    root.protocol("WM_DELETE_WINDOW", lambda: (_cleanup(root)))
    root.mainloop()


def _cleanup(root):
    if hasattr(root, '_app'):
        root._app._cleanup_certs()
    root.destroy()


if __name__ == "__main__":
    main()
