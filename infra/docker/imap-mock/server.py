#!/usr/bin/env python3
"""Minimal IMAP mock for the cleartext-auth check.

vuln:    CAPABILITY reply omits LOGINDISABLED -> plaintext LOGIN allowed pre-TLS.
patched: CAPABILITY reply advertises LOGINDISABLED + STARTTLS -> plaintext refused.
Speaks just enough IMAP to answer the banner + one CAPABILITY command.
"""
import os
import socket
import threading

VULN = os.environ.get("IMAP_MODE", "patched") == "vuln"
PORT = int(os.environ.get("IMAP_PORT", "143"))

BANNER = b"* OK noctis IMAP4rev1 ready\r\n"


def caps_reply(tag: str) -> bytes:
    if VULN:
        caps = "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n"
    else:
        caps = "* CAPABILITY IMAP4rev1 LOGINDISABLED STARTTLS\r\n"
    return (caps + f"{tag} OK CAPABILITY completed\r\n").encode()


def handle(conn):
    f = conn.makefile("rb")
    try:
        conn.sendall(BANNER)
        while True:
            line = f.readline()
            if not line:
                break
            parts = line.decode("utf-8", "replace").split()
            if not parts:
                continue
            tag = parts[0]
            cmd = parts[1].upper() if len(parts) > 1 else ""
            if cmd == "CAPABILITY":
                conn.sendall(caps_reply(tag))
            elif cmd == "LOGOUT":
                conn.sendall(b"* BYE\r\n" + f"{tag} OK LOGOUT completed\r\n".encode())
                break
            else:
                conn.sendall(f"{tag} OK\r\n".encode())
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
