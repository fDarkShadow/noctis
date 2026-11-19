#!/usr/bin/env python3
"""Minimal Memcached TCP mock. vuln: `stats` returns STAT lines; patched: auth error."""
import os, socket, threading
VULN = os.environ.get("MC_MODE", "patched") == "vuln"
PORT = int(os.environ.get("MC_PORT", "11211"))
STATS = (b"STAT pid 1\r\nSTAT version 1.6.21\r\nSTAT uptime 3600\r\n"
         b"STAT curr_connections 5\r\nEND\r\n")
DENY = b"CLIENT_ERROR authentication required\r\n"
def handle(c):
    f = c.makefile("rb")
    try:
        c.settimeout(5)
        line = f.readline()
        if line.strip() == b"stats":
            c.sendall(STATS if VULN else DENY)
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
