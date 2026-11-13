#!/usr/bin/env python3
"""Minimal Telnet mock for the exposure check.

vuln:    on connect, sends IAC option negotiation (DO/WILL ...) followed by a
         system banner and a "login:" prompt, like a real telnetd.
patched: no telnet service — accepts the connection and closes it immediately
         with no banner (simulates another service / nothing speaking telnet).
"""
import os
import socket
import threading

VULN = os.environ.get("TELNET_MODE", "patched") == "vuln"
PORT = int(os.environ.get("TELNET_PORT", "23"))

IAC = 0xFF
DO, WILL = 0xFD, 0xFB
# A small, realistic IAC negotiation: DO TERMINAL-TYPE(24), DO NAWS(31),
# WILL ECHO(1), WILL SUPPRESS-GO-AHEAD(3).
NEGOTIATION = bytes([
    IAC, DO, 24,
    IAC, DO, 31,
    IAC, WILL, 1,
    IAC, WILL, 3,
])
BANNER = b"\r\nUbuntu 22.04.3 LTS\r\nnoctis-host login: "


def handle(conn):
    try:
        if VULN:
            conn.sendall(NEGOTIATION + BANNER)
        # patched: send nothing, just close.
    except OSError:
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
