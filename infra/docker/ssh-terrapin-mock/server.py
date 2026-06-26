"""Mock SSH server for CVE-2023-48795 (Terrapin) detection testing.

Vuln mode: KEXINIT without kex-strict-s-v00@openssh.com (pre-9.6 behaviour)
Patched mode: KEXINIT includes kex-strict-s-v00@openssh.com (OpenSSH >= 9.6)

The server only implements the version exchange + KEXINIT — it does not
complete the handshake. That is sufficient for the noctis detection logic
which reads the KEXINIT and disconnects.
"""
import os
import socket
import struct
import threading

VULN_MODE = os.environ.get("SSH_MOCK_MODE", "patched") == "vuln"
PORT = int(os.environ.get("PORT", 22))

# Algorithm lists for the two modes
_KEX_VULN = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256"
_KEX_PATCHED = (
    "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,"
    "ext-info-s,kex-strict-s-v00@openssh.com"
)
_HOSTKEY = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
_ENC = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com"
_MAC = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256"
_COMP = "none,zlib@openssh.com"


def _namelist(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def _build_kexinit(vuln: bool) -> bytes:
    kex = _KEX_VULN if vuln else _KEX_PATCHED
    payload = bytes([20])  # SSH_MSG_KEXINIT
    payload += os.urandom(16)  # cookie
    payload += _namelist(kex)
    payload += _namelist(_HOSTKEY)
    payload += _namelist(_ENC)   # enc c2s
    payload += _namelist(_ENC)   # enc s2c
    payload += _namelist(_MAC)   # mac c2s
    payload += _namelist(_MAC)   # mac s2c
    payload += _namelist(_COMP)  # comp c2s
    payload += _namelist(_COMP)  # comp s2c
    payload += _namelist("")     # lang c2s
    payload += _namelist("")     # lang s2c
    payload += bytes([0])        # first_kex_follows
    payload += struct.pack(">I", 0)  # reserved

    # Padding to multiple of 8 bytes (minimum 4)
    total = 5 + len(payload)  # 4 (pkt_len field) + 1 (pad_len field) + payload
    pad = 8 - (total % 8)
    if pad < 4:
        pad += 8
    padding = os.urandom(pad)

    pkt_len = 1 + len(payload) + pad  # pad_len_field + payload + padding
    return struct.pack(">IB", pkt_len, pad) + payload + padding


KEXINIT_PKT = _build_kexinit(VULN_MODE)
BANNER = b"SSH-2.0-OpenSSH_9.5p1 Alpine Linux\r\n" if VULN_MODE else b"SSH-2.0-OpenSSH_9.6 Alpine Linux\r\n"


def handle(conn: socket.socket):
    try:
        # Send banner + KEXINIT together immediately on connect, without waiting
        # for the client banner. This ensures noctis's single read() call receives
        # both the banner and the KEXINIT in one burst (real OpenSSH sends KEXINIT
        # only after receiving client banner, but for test purposes sending early
        # lets the detector read everything in one syscall).
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
    print(f"SSH Terrapin mock on :{PORT} (mode={mode})", flush=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(32)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
