#!/usr/bin/env python3
"""Fake SSH server that advertises Erlang/OTP SSH banner for CVE-2025-32433.

Sends a raw SSH version string + minimal KEXINIT so that noctis ssh_check
can read the banner. No real SSH handshake is completed.
"""
import os
import socket
import struct
import threading

VULN_MODE = os.environ.get("ERLANG_SSH_MODE", "patched") == "vuln"
PORT = int(os.environ.get("PORT", 22))

# Erlang/OTP SSH library 5.1 (OTP 26.2.x) — vulnerable
BANNER_VULN = b"SSH-2.0-Erlang/5.1\r\n"
# Erlang/OTP SSH library 5.3.3 (OTP 27.3.3+) — patched
BANNER_PATCHED = b"SSH-2.0-Erlang/5.3.3\r\n"

BANNER = BANNER_VULN if VULN_MODE else BANNER_PATCHED

_KEX_ALGOS = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256"
_HOSTKEY = "ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519"
_ENC = "aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
_MAC = "hmac-sha2-256,hmac-sha2-512"
_COMP = "none"


def _namelist(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def _build_kexinit() -> bytes:
    payload = bytes([20])       # SSH_MSG_KEXINIT
    payload += os.urandom(16)  # cookie
    payload += _namelist(_KEX_ALGOS)
    payload += _namelist(_HOSTKEY)
    payload += _namelist(_ENC)
    payload += _namelist(_ENC)
    payload += _namelist(_MAC)
    payload += _namelist(_MAC)
    payload += _namelist(_COMP)
    payload += _namelist(_COMP)
    payload += _namelist("")
    payload += _namelist("")
    payload += bytes([0])
    payload += struct.pack(">I", 0)
    total = 5 + len(payload)
    pad = 8 - (total % 8)
    if pad < 4:
        pad += 8
    padding = os.urandom(pad)
    pkt_len = 1 + len(payload) + pad
    return struct.pack(">IB", pkt_len, pad) + payload + padding


KEXINIT_PKT = _build_kexinit()


def handle(conn: socket.socket):
    try:
        conn.sendall(BANNER + KEXINIT_PKT)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    mode = "vuln" if VULN_MODE else "patched"
    print(f"Erlang/OTP SSH mock on :{PORT} (mode={mode}, banner={BANNER.strip().decode()})", flush=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(32)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
