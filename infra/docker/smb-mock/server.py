#!/usr/bin/env python3
"""Minimal SMB mock for the SMBv1-enabled and SMB-signing checks.

SMB1 NEGOTIATE request (general/smbv1-enabled) — the request is not parsed,
the detection matches the response's SMB signature:
vuln:    an SMB1 message (signature 0xFF 'SMB') -> SMBv1 enabled.
patched: an SMB2 message (signature 0xFE 'SMB') -> SMBv1 disabled.

SMB2 NEGOTIATE request (general/smb-signing-not-required) — signature 0xFE 'SMB'
at byte 4. The mock picks the highest offered dialect it supports and answers a
proper SMB2 NEGOTIATE response:
vuln:    SecurityMode 0x01 (signing enabled, NOT required).
patched: SecurityMode 0x03 (signing enabled AND required).
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

SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
SMB2_SECURITY_MODE = 0x01 if VULN else 0x03  # 0x01 signing enabled, 0x02 required


def smb2_negotiate_response(req: bytes) -> bytes:
    """SMB2 NEGOTIATE response for an SMB2 NEGOTIATE request (NBSS-framed)."""
    smb = req[4:]
    count = struct.unpack_from("<H", smb, 66)[0] if len(smb) >= 68 else 0
    offered = [struct.unpack_from("<H", smb, 100 + 2 * i)[0]
               for i in range(count) if len(smb) >= 102 + 2 * i]
    common = [d for d in offered if d in SMB2_DIALECTS]
    dialect = max(common) if common else 0x0202

    hdr = b"\xfeSMB" + struct.pack("<HHI", 64, 0, 0)          # size, credit charge, status
    hdr += struct.pack("<HHII", 0, 1, 0x01, 0)                  # NEGOTIATE, credits, SERVER_TO_REDIR
    hdr += b"\x00" * 8 + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 8 + b"\x00" * 16
    ctx = b""
    if dialect == 0x0311:
        # SMB2_PREAUTH_INTEGRITY_CAPABILITIES: SHA-512, 32-byte salt.
        data = struct.pack("<HHH", 1, 32, 1) + b"\x00" * 32
        ctx = struct.pack("<HHI", 1, len(data), 0) + data
    body = struct.pack("<HHHH", 65, SMB2_SECURITY_MODE, dialect, 1 if ctx else 0)
    body += b"noctis-smb-mock!"                                 # ServerGuid (16 B)
    body += struct.pack("<IIII", 0, 65536, 65536, 65536)        # caps, max transact/read/write
    body += b"\x00" * 16                                        # SystemTime, ServerStartTime
    body += struct.pack("<HHI", 128, 0, 128 if ctx else 0)      # sec buffer off/len, ctx offset
    msg = hdr + body + ctx
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg


def handle(conn):
    try:
        conn.settimeout(5)
        req = conn.recv(1024)
        if req[4:8] == b"\xfeSMB":
            conn.sendall(smb2_negotiate_response(req))
        else:
            conn.sendall(REPLY)  # SMB1 NEGOTIATE (or anything else): unchanged reply
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
