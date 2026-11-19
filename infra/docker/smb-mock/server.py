#!/usr/bin/env python3
"""Minimal SMB mock for the SMBv1-enabled check.

Reads an SMB1 NEGOTIATE request and replies with a NEGOTIATE response:
vuln:    an SMB1 message (signature 0xFF 'SMB') -> SMBv1 enabled.
patched: an SMB2 message (signature 0xFE 'SMB') -> SMBv1 disabled.

The request is not parsed; the detection matches the response's SMB signature.
"""
import os
import socket
import struct
import threading

VULN = os.environ.get("SMB_MODE", "patched") == "vuln"
PORT = int(os.environ.get("SMB_PORT", "445"))


def negotiate_response(signature: bytes) -> bytes:
    # Minimal NEGOTIATE response header with the given protocol signature.
    hdr = signature + bytes([0x72]) + b"\x00\x00\x00\x00" + bytes([0x98])
    hdr += struct.pack("<H", 0xC853) + b"\x00\x00" + b"\x00" * 8
    hdr += b"\x00\x00" + b"\x00\x00" + struct.pack("<H", 0x4B2F) + b"\x00\x00" + b"\x00\x00"
    body = hdr + b"\x01\x00\x00"  # wordcount + minimal params/bytecount
    # NBSS: 1-byte session type 0x00 + 3-byte big-endian length.
    return b"\x00" + struct.pack(">I", len(body))[1:] + body


REPLY = negotiate_response(b"\xffSMB" if VULN else b"\xfeSMB")


def handle(conn):
    try:
        conn.settimeout(5)
        conn.recv(1024)  # read the SMB1 NEGOTIATE request (ignored)
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
