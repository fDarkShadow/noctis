#!/usr/bin/env python3
"""Minimal PostgreSQL mock. vuln: AuthenticationOk (trust); patched: MD5 password."""
import os, socket, struct, threading
VULN = os.environ.get("PG_MODE", "patched") == "vuln"
PORT = int(os.environ.get("PG_PORT", "5432"))
AUTH_OK = b"R" + struct.pack(">II", 8, 0) + b"Z" + struct.pack(">I", 5) + b"I"   # +ReadyForQuery
AUTH_MD5 = b"R" + struct.pack(">II", 12, 5) + b"\x01\x02\x03\x04"
def handle(c):
    try:
        c.settimeout(5)
        c.recv(1024)  # StartupMessage (ignored)
        c.sendall(AUTH_OK if VULN else AUTH_MD5)
    except OSError:
        pass
    finally:
        c.close()
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT)); s.listen(16)
    while True:
        c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
if __name__ == "__main__":
    main()
