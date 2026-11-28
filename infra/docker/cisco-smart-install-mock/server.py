#!/usr/bin/env python3
"""Minimal Cisco Smart Install (SMI) mock for the CVE-2018-0171 exposure check.

Pure byte-string simulation of the SMI protocol on TCP 4786 — a listening
socket that returns canned bytes only. No subprocess, exec, eval or file I/O.

The feed sends the benign SMI identify frame (six 32-bit big-endian words,
first word 0x00000001). A genuine SMI-enabled device answers with the fixed
24-byte SMI identify response whose first word is 0x00000004.

vuln:    reply with the real SMI identify response -> Smart Install enabled.
patched: Smart Install disabled -> no SMI response (close the connection).
"""
import os
import socket
import threading

VULN = os.environ.get("SMI_MODE", "patched") == "vuln"
PORT = int(os.environ.get("SMI_PORT", "4786"))

# The standard SMI identify request the feed sends (for a sanity check only).
SMI_IDENTIFY_REQUEST = bytes.fromhex("000000010000000100000004000000080000000100000000")
# The SMI identify response a Smart Install enabled device returns.
SMI_IDENTIFY_RESPONSE = bytes.fromhex("000000040000000000000003000000080000000100000000")


def handle(conn):
    try:
        conn.settimeout(5)
        req = conn.recv(1024)
        if not req:
            return
        # Vuln mode: answer the SMI identify frame with the SMI identify
        # response. Patched mode: Smart Install is off, so nothing answers.
        if VULN and req[:8] == SMI_IDENTIFY_REQUEST[:8]:
            conn.sendall(SMI_IDENTIFY_RESPONSE)
    except OSError:  # malformed / truncated request: just close
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
