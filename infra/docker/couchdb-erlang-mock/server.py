#!/usr/bin/env python3
"""Minimal Erlang distribution-protocol mock for CVE-2022-24706 (CouchDB).

The real vulnerability: a CouchDB node ships with a default, well-known Erlang
magic cookie ("monster") on an exposed distribution port, so any peer can
complete the distribution handshake and gain code execution. The detection
feed speaks that binary handshake on one persistent socket (noctis issue #316):

    client → NAME_MSG ('n')                                     (frame 1)
    server → challenge ('n', 4-byte challenge at byte offset 9)
    client → challenge-reply ('r', [our_challenge:4][digest:16]) (frame 2)
    server → ack ('a' + digest)  iff the digest matches the cookie

This mock implements only enough of that exchange to exercise the check:

  vuln:    COOKIE = "monster" (the shipped default). The client's digest,
           computed as MD5("monster" + decimal(challenge)), matches → the mock
           sends a non-empty ack → the node is confirmed exploitable.
  patched: COOKIE = a strong random value. The client still uses "monster", so
           the digest never matches → the mock replies with nothing → clean.

No real BSON/ETF parsing — it returns a fixed challenge and validates the
trailing 16 digest bytes of frame 2, which is enough for the detection.
"""
import hashlib
import os
import socket
import struct
import threading

COOKIE = os.environ.get("ERL_COOKIE", "monster")
PORT = int(os.environ.get("ERL_DIST_PORT", "9100"))

# Fixed challenge the mock hands out (byte offset 9 of frame 1, big-endian u32).
CHALLENGE = 0x01020304
NODE_NAME = b"noctis@mock"


def challenge_frame() -> bytes:
    # 'n' message: tag, version(2), flags(4), challenge(4), node name.
    # The 2-byte length prefix puts the challenge at byte offset 9.
    body = (
        b"n"
        + struct.pack(">H", 5)          # version
        + struct.pack(">I", 0)          # flags
        + struct.pack(">I", CHALLENGE)  # challenge  → bytes 9..13
        + NODE_NAME
    )
    return struct.pack(">H", len(body)) + body


def expected_digest() -> bytes:
    # Erlang gen_digest: MD5(cookie ++ integer_to_list(challenge)).
    return hashlib.md5(COOKIE.encode() + str(CHALLENGE).encode()).digest()


def ack_frame() -> bytes:
    # 'a' ack carrying the server's own digest (non-empty = handshake accepted).
    body = b"a" + expected_digest()
    return struct.pack(">H", len(body)) + body


def handle(conn):
    try:
        conn.settimeout(5)
        # frame 1: NAME_MSG — reply with the challenge.
        if not conn.recv(4096):
            return
        conn.sendall(challenge_frame())
        # frame 2: challenge-reply — validate the trailing 16 digest bytes.
        frame2 = conn.recv(4096)
        if len(frame2) >= 16 and frame2[-16:] == expected_digest():
            conn.sendall(ack_frame())
        # else: wrong cookie → say nothing (patched behaviour).
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
