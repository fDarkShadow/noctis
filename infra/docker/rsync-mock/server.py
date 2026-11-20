#!/usr/bin/env python3
"""Minimal rsync-daemon mock for the anonymous module-listing check.

Greets with @RSYNCD, reads the client version and the module-list request
(empty line), then:
vuln:    lists modules and ends with @RSYNCD: EXIT -> anonymous listing allowed.
patched: returns @ERROR: access denied -> listing refused.
"""
import os
import socket
import threading

VULN = os.environ.get("RSYNC_MODE", "patched") == "vuln"
PORT = int(os.environ.get("RSYNC_PORT", "873"))

GREETING = b"@RSYNCD: 31.0\n"

VULN_LIST = (
    "data            \tPublic data share\n"
    "backup          \tNightly backups\n"
    "@RSYNCD: EXIT\n"
).encode()
PATCHED_REPLY = b"@ERROR: access denied to module listing\n"


def handle(conn):
    f = conn.makefile("rb")
    try:
        conn.settimeout(5)
        conn.sendall(GREETING)
        f.readline()  # client version
        f.readline()  # module-list request (empty line)
        conn.sendall(VULN_LIST if VULN else PATCHED_REPLY)
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
