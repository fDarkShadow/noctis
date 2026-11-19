#!/usr/bin/env python3
"""Minimal VNC/RFB mock for the no-authentication check.

The RFB 3.8 handshake: server sends its ProtocolVersion, reads the client's
version, then sends the security-types list [count][type...].

vuln:    offers [None(1), VNCAuth(2)] -> connecting needs no password.
patched: offers [VNCAuth(2)] only.
"""
import os
import socket
import threading

VULN = os.environ.get("VNC_MODE", "patched") == "vuln"
PORT = int(os.environ.get("VNC_PORT", "5900"))

VERSION = b"RFB 003.008\n"


def sec_types() -> bytes:
    if VULN:
        return bytes([2, 1, 2])  # count=2: None, VNCAuth
    return bytes([1, 2])         # count=1: VNCAuth only


def handle(conn):
    try:
        conn.settimeout(5)
        conn.sendall(VERSION)
        # read the client's 12-byte ProtocolVersion (ignored)
        try:
            conn.recv(32)
        except OSError:
            pass
        conn.sendall(sec_types())
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
