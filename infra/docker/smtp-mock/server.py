#!/usr/bin/env python3
"""Minimal SMTP control-channel mock for the open-relay check.

vuln:    accepts RCPT TO for any (external) recipient -> 250.
patched: rejects an external recipient -> 554 Relay access denied.
Only the envelope dialogue (EHLO/MAIL/RCPT/QUIT) is modelled; DATA is not needed.
"""
import os
import socket
import threading

VULN = os.environ.get("SMTP_MODE", "patched") == "vuln"
PORT = int(os.environ.get("SMTP_PORT", "25"))


def handle(conn):
    conn.sendall(b"220 mail.noctis-mock ESMTP ready\r\n")
    f = conn.makefile("rb")
    try:
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode("utf-8", "replace").strip()
            upper = cmd.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                conn.sendall(b"250-mail.noctis-mock Hello\r\n250 SIZE 10240000\r\n")
            elif upper.startswith("MAIL FROM"):
                conn.sendall(b"250 2.1.0 Sender ok\r\n")
            elif upper.startswith("RCPT TO"):
                if VULN:
                    conn.sendall(b"250 2.1.5 Recipient ok\r\n")
                else:
                    conn.sendall(b"554 5.7.1 Relay access denied\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 2.0.0 Bye\r\n")
                break
            else:
                conn.sendall(b"502 5.5.2 Command not implemented\r\n")
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
