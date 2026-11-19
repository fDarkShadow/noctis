#!/usr/bin/env python3
"""Minimal X11 mock. vuln: setup Success (0x01); patched: Failed (0x00)."""
import os, socket, threading
VULN = os.environ.get("X11_MODE", "patched") == "vuln"
PORT = int(os.environ.get("X11_PORT", "6000"))
SUCCESS = bytes([0x01, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00])
reason = b"No protocol specified"
FAILED = bytes([0x00, len(reason), 0x0b, 0x00, 0x00, 0x00, (len(reason)+3)//4, 0x00]) + reason
def handle(c):
    try:
        c.settimeout(5); c.recv(64)
        c.sendall(SUCCESS if VULN else FAILED)
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
