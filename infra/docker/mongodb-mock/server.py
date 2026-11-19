#!/usr/bin/env python3
"""Minimal MongoDB wire-protocol mock for the unauthenticated-exposure check.

The client sends an OP_MSG `listDatabases` command. This mock replies with a
canned OP_MSG:

vuln:    a successful listDatabases reply (contains `databases` + `totalSize`,
         ok:1) — i.e. the node served the DB listing without authentication.
patched: an auth error (`command listDatabases requires authentication`,
         codeName Unauthorized, ok:0) — no `totalSize`.

It does not implement real BSON parsing of the request; it just reads the
incoming frame and returns the appropriate reply, which is enough to exercise
the detection (which matches ASCII markers in the reply).
"""
import os
import socket
import struct
import threading

VULN = os.environ.get("MONGO_MODE", "patched") == "vuln"
PORT = int(os.environ.get("MONGO_PORT", "27017"))

OP_MSG = 2013


# ── tiny BSON encoders (only what the canned replies need) ──────────────────
def _cstr(s: str) -> bytes:
    return s.encode() + b"\x00"


def e_str(k: str, v: str) -> bytes:
    vb = v.encode() + b"\x00"
    return b"\x02" + _cstr(k) + struct.pack("<i", len(vb)) + vb


def e_i32(k: str, v: int) -> bytes:
    return b"\x10" + _cstr(k) + struct.pack("<i", v)


def e_i64(k: str, v: int) -> bytes:
    return b"\x12" + _cstr(k) + struct.pack("<q", v)


def e_double(k: str, v: float) -> bytes:
    return b"\x01" + _cstr(k) + struct.pack("<d", v)


def bson_doc(*elems: bytes) -> bytes:
    body = b"".join(elems) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def op_msg(doc: bytes, response_to: int = 1) -> bytes:
    body = struct.pack("<i", 0) + b"\x00" + doc  # flagBits=0, section kind 0 (body)
    header = struct.pack("<iiii", 16 + len(body), 2, response_to, OP_MSG)
    return header + body


def reply() -> bytes:
    if VULN:
        doc = bson_doc(
            e_str("databases", "admin,config,local"),
            e_i64("totalSize", 811008),
            e_i64("totalSizeMb", 0),
            e_double("ok", 1.0),
        )
    else:
        doc = bson_doc(
            e_double("ok", 0.0),
            e_str("errmsg", "command listDatabases requires authentication"),
            e_i32("code", 13),
            e_str("codeName", "Unauthorized"),
        )
    return op_msg(doc)


def handle(conn):
    try:
        # Read the client's request frame (length-prefixed); size is ignored.
        conn.settimeout(5)
        _ = conn.recv(4096)
        conn.sendall(reply())
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
