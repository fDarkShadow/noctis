#!/usr/bin/env python3
"""Raw TCP mock of the Serv-U FTP control-channel greeting (CVE-2026-28318).

Only the 220 welcome banner is modelled: it is sent on connect, then the
connection is held open until the client closes it or sends a line (any line
gets a 221 and a close). No FTP command is implemented, and the deflate DoS
itself is not modelled: the feed must never need it.

vuln:    220 Serv-U FTP Server v15.5.3 ready...
patched: 220 Serv-U FTP Server v15.5.4 Hotfix 1 ready...
SERVU_VERSION overrides the version text (used by the boundary test hosts).
Plaintext on $FTP_PORT (default 21).
"""
import os
import socket
import threading

VULN = os.environ.get("SERVU_MODE", "patched") == "vuln"
PORT = int(os.environ.get("FTP_PORT", "21"))
VERSION = os.environ.get("SERVU_VERSION") or ("15.5.3" if VULN else "15.5.4 Hotfix 1")
BANNER = f"220 Serv-U FTP Server v{VERSION} ready...\r\n".encode()


def handle(conn):
    try:
        conn.settimeout(10)
        conn.sendall(BANNER)
        if conn.recv(1024):
            conn.sendall(b"221 Goodbye!\r\n")
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
