#!/usr/bin/env python3
"""Minimal Cassandra CQL mock. vuln: READY (no auth); patched: AUTHENTICATE."""
import os, socket, threading
VULN = os.environ.get("CQL_MODE", "patched") == "vuln"
PORT = int(os.environ.get("CQL_PORT", "9042"))
READY = bytes([0x84, 0x00, 0x00, 0x00, 0x02, 0, 0, 0, 0])
# AUTHENTICATE with a [string] body naming the authenticator
AUTHN_BODY = (lambda s: (len(s).to_bytes(2, "big") + s))(b"org.apache.cassandra.auth.PasswordAuthenticator")
AUTHN = bytes([0x84, 0x00, 0x00, 0x00, 0x03]) + len(AUTHN_BODY).to_bytes(4, "big") + AUTHN_BODY
def handle(c):
    try:
        c.settimeout(5); c.recv(1024)
        c.sendall(READY if VULN else AUTHN)
    except OSError:
        pass
    finally:
        c.close()
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT)); s.listen(16)
    while True:
        c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
if __name__ == "__main__":
    main()
