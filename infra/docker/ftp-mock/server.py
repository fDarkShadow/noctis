#!/usr/bin/env python3
"""Minimal FTP control-channel mock for the anonymous-FTP check.

vuln:    accepts USER anonymous + any password -> 230 Login successful.
patched: any login -> 530 Login incorrect.
Plaintext FTP on $FTP_PORT (default 21); only the control dialogue is modelled.
"""
import os
import socket
import threading

VULN = os.environ.get("FTP_MODE", "patched") == "vuln"
PORT = int(os.environ.get("FTP_PORT", "21"))


def handle(conn):
    conn.sendall(b"220 noctis-ftp ready\r\n")
    f = conn.makefile("rb")
    user = None
    try:
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode("utf-8", "replace").strip()
            upper = cmd.upper()
            if upper.startswith("USER"):
                user = cmd.split(" ", 1)[1].strip() if " " in cmd else ""
                conn.sendall(b"331 Please specify the password.\r\n")
            elif upper.startswith("PASS"):
                if VULN and user is not None and user.lower() == "anonymous":
                    conn.sendall(b"230 Login successful.\r\n")
                else:
                    conn.sendall(b"530 Login incorrect.\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"502 Command not implemented.\r\n")
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
