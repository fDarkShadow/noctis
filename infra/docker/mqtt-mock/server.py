#!/usr/bin/env python3
"""Minimal MQTT mock. vuln: CONNACK accepted (rc 0); patched: not authorized (rc 5)."""
import os, socket, threading
VULN = os.environ.get("MQTT_MODE", "patched") == "vuln"
PORT = int(os.environ.get("MQTT_PORT", "1883"))
ACCEPT = bytes([0x20, 0x02, 0x00, 0x00])
DENY = bytes([0x20, 0x02, 0x00, 0x05])
def handle(c):
    try:
        c.settimeout(5)
        c.recv(1024)  # CONNECT (ignored)
        c.sendall(ACCEPT if VULN else DENY)
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
