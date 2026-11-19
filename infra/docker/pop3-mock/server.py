#!/usr/bin/env python3
"""Minimal POP3 mock for the cleartext-auth check.

vuln:    CAPA reply omits STLS -> plaintext USER/PASS allowed without TLS.
patched: CAPA reply advertises STLS -> TLS required before auth.
Speaks just enough POP3 to answer the banner + a CAPA command.
"""
import os
import socket
import threading

VULN = os.environ.get("POP3_MODE", "patched") == "vuln"
PORT = int(os.environ.get("POP3_PORT", "110"))

BANNER = b"+OK noctis POP3 ready\r\n"

if VULN:
    CAPA = (
        "+OK Capability list follows\r\n"
        "USER\r\nTOP\r\nUIDL\r\nSASL PLAIN LOGIN\r\n.\r\n"
    )
else:
    CAPA = (
        "+OK Capability list follows\r\n"
        "STLS\r\nUSER\r\nTOP\r\nUIDL\r\n.\r\n"
    )


def handle(conn):
    f = conn.makefile("rb")
    try:
        conn.sendall(BANNER)
        while True:
            line = f.readline()
            if not line:
                break
            word = line.decode("utf-8", "replace").strip().split(" ")[0].upper()
            if not word:
                continue
            if word == "CAPA":
                conn.sendall(CAPA.encode())
            elif word == "QUIT":
                conn.sendall(b"+OK bye\r\n")
                break
            else:
                conn.sendall(b"+OK\r\n")
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
