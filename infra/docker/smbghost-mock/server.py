#!/usr/bin/env python3
"""Minimal SMB mock for the SMBGhost check (general/CVE-2020-0796).

Answers an SMB2 NEGOTIATE request (ProtocolId 0xFE 'SMB' at byte 4) with a
proper SMB2 NEGOTIATE response, picking the highest offered dialect it supports.
On a 3.1.1 reply it always includes the SMB2_PREAUTH_INTEGRITY_CAPABILITIES
context (required for a real server to accept 3.1.1); only in vuln mode does it
additionally advertise an SMB2_COMPRESSION_CAPABILITIES context (ContextType
0x0003) — the exact fingerprint that makes a host SMBGhost-exposed.

vuln:    dialect 3.1.1 + SMB2_COMPRESSION_CAPABILITIES context (compression on).
patched: dialect 3.1.1 WITHOUT any compression context (KB4551762 / mitigation).

This is a pure byte-string simulation: a raw TCP server answering a fixed frame.
It never decompresses anything, runs no command and touches no file — the
SMBGhost overflow is NEVER reproduced, only its safe precondition is modelled.
"""
import os
import socket
import struct
import threading

VULN = os.environ.get("SMBGHOST_MODE", "patched") == "vuln"
PORT = int(os.environ.get("SMB_PORT", "445"))

SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
SMB2_SECURITY_MODE = 0x01  # signing enabled (not required) — irrelevant to this check


def _pad8(buf: bytes) -> bytes:
    if len(buf) % 8:
        buf += b"\x00" * (8 - len(buf) % 8)
    return buf


def smb2_negotiate_response(req: bytes) -> bytes:
    """SMB2 NEGOTIATE response for an SMB2 NEGOTIATE request (NBSS-framed)."""
    smb = req[4:]
    count = struct.unpack_from("<H", smb, 66)[0] if len(smb) >= 68 else 0
    count = min(count, max(0, (len(smb) - 100) // 2))  # never read past the buffer
    offered = [struct.unpack_from("<H", smb, 100 + 2 * i)[0] for i in range(count)]
    common = [d for d in offered if d in SMB2_DIALECTS]
    dialect = max(common) if common else 0x0202

    hdr = b"\xfeSMB" + struct.pack("<HHI", 64, 0, 0)          # size, credit charge, status
    hdr += struct.pack("<HHII", 0, 1, 0x01, 0)                  # NEGOTIATE, credits, SERVER_TO_REDIR
    hdr += b"\x00" * 8 + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 16

    contexts = b""
    ctx_count = 0
    if dialect == 0x0311:
        # SMB2_PREAUTH_INTEGRITY_CAPABILITIES: SHA-512, 32-byte salt (always present).
        data = struct.pack("<HHH", 1, 32, 1) + b"\x00" * 32
        contexts += struct.pack("<HHI", 1, len(data), 0) + data
        ctx_count += 1
        contexts = _pad8(contexts)
        if VULN:
            # SMB2_COMPRESSION_CAPABILITIES: count=1, pad, flags=0, LZ77+Huffman(3).
            cdata = struct.pack("<HHI", 1, 0, 0) + struct.pack("<H", 3)
            contexts += struct.pack("<HHI", 3, len(cdata), 0) + cdata
            ctx_count += 1

    body = struct.pack("<HHHH", 65, SMB2_SECURITY_MODE, dialect, ctx_count)
    body += b"noctis-smbghost!"                                 # ServerGuid (16 B)
    body += struct.pack("<IIII", 0, 65536, 65536, 65536)        # caps, max transact/read/write
    body += b"\x00" * 16                                        # SystemTime, ServerStartTime
    body += struct.pack("<HHI", 128, 0, 128 if contexts else 0) # sec buffer off/len, ctx offset
    msg = hdr + body + contexts
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg


def handle(conn):
    try:
        conn.settimeout(5)
        req = conn.recv(1024)
        if len(req) >= 8 and req[4:8] == b"\xfeSMB":
            conn.sendall(smb2_negotiate_response(req))
        # Anything that is not an SMB2 request: stay silent and just close.
    except (OSError, struct.error):  # malformed / truncated request: just close
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
