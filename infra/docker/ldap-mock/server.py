#!/usr/bin/env python3
"""Minimal LDAP mock for the anonymous-bind check.

Reads a BER bindRequest and replies with a bindResponse:
vuln:    resultCode success (0)                    -> anonymous bind allowed.
patched: resultCode inappropriateAuthentication(48) -> anonymous bind refused.

Only enough of LDAP is implemented to answer one bind; the request is not
parsed (the detection matches the response resultCode).
"""
import os
import socket
import threading

VULN = os.environ.get("LDAP_MODE", "patched") == "vuln"
PORT = int(os.environ.get("LDAP_PORT", "389"))


def bind_response(code: int) -> bytes:
    # [APPLICATION 1] SEQUENCE { resultCode ENUMERATED, matchedDN "", errorMessage "" }
    content = bytes([0x0A, 0x01, code, 0x04, 0x00, 0x04, 0x00])
    resp = bytes([0x61, len(content)]) + content
    msg = bytes([0x02, 0x01, 0x01]) + resp  # messageID 1
    return bytes([0x30, len(msg)]) + msg


REPLY = bind_response(0x00 if VULN else 0x30)  # 0 success / 48 inappropriateAuthentication


def handle(conn):
    try:
        conn.settimeout(5)
        conn.recv(1024)  # read the bindRequest (ignored)
        conn.sendall(REPLY)
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
