#!/usr/bin/env python3
"""Minimal memcached-UDP mock for the amplification/exposure check.

vuln:    answers a UDP `stats` with the 8-byte memcached frame header + STAT lines.
patched: UDP disabled — binds but never replies, so the probe times out.
"""
import os
import socket

VULN = os.environ.get("MEMCACHED_MODE", "patched") == "vuln"
PORT = int(os.environ.get("MEMCACHED_PORT", "11211"))

STATS = (
    b"STAT pid 1\r\n"
    b"STAT version 1.6.9\r\n"
    b"STAT bytes 0\r\n"
    b"STAT curr_connections 1\r\n"
    b"END\r\n"
)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        if not VULN:
            continue  # UDP disabled → no reply
        # echo the client's 8-byte UDP frame header, then the stats payload
        header = data[:8] if len(data) >= 8 else b"\x00" * 8
        if b"stats" in data.lower():
            s.sendto(header + STATS, addr)


if __name__ == "__main__":
    main()
