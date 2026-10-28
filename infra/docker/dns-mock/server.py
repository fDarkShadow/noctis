#!/usr/bin/env python3
"""Minimal UDP DNS mock for the open-resolver check (no deps).

vuln:    acts as an open resolver — answers a recursive query with
         recursion-available + NOERROR (flags 0x8180) and an A record.
patched:  refuses recursion — REFUSED (flags 0x8185), no answer.
Echoes the query's transaction id and question section.
"""
import os
import socket

VULN = os.environ.get("DNS_MODE", "patched") == "vuln"
PORT = int(os.environ.get("DNS_PORT", "53"))


def build_response(query: bytes) -> bytes:
    txid = query[0:2]
    question = query[12:]  # our probe sends a single question, no extra records
    if VULN:
        flags = b"\x81\x80"                      # QR, RD, RA, rcode=0 (NOERROR)
        counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"  # qd=1 an=1 ns=0 ar=0
        answer = (
            b"\xc0\x0c"            # name pointer -> offset 12 (the question)
            b"\x00\x01\x00\x01"    # type A, class IN
            b"\x00\x00\x01\x00"    # ttl 256
            b"\x00\x04"            # rdlength 4
            b"\xc0\x00\x02\x01"    # 192.0.2.1
        )
        return txid + flags + counts + question + answer
    else:
        flags = b"\x81\x85"                      # QR, RD, RA, rcode=5 (REFUSED)
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"  # qd=1 an=0
        return txid + flags + counts + question


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        if len(data) < 12:
            continue
        s.sendto(build_response(data), addr)


if __name__ == "__main__":
    main()
