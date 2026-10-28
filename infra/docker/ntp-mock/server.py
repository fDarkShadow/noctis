#!/usr/bin/env python3
"""Minimal UDP NTP mock for the monlist check (CVE-2013-5211), no deps.

vuln:    answers a mode-7 MON_GETLIST_1 request with a mode-7 response carrying a
         (fake) monitor list entry — i.e. monlist is enabled.
patched: ignores mode-7 requests (monlist disabled) — no reply.
"""
import os
import socket

VULN = os.environ.get("NTP_MODE", "patched") == "vuln"
PORT = int(os.environ.get("NTP_PORT", "123"))


def is_mode7_monlist(data: bytes) -> bool:
    if len(data) < 4:
        return False
    mode = data[0] & 0x07
    return mode == 7 and data[2] == 0x03 and data[3] == 0x2A  # impl XNTPD, req MON_GETLIST_1


def build_monlist_response() -> bytes:
    # byte0: response(0x80) | more(0x40) | version 2 (0x10) | mode 7 (0x07) = 0xD7
    header = bytes([0xD7, 0x00, 0x03, 0x2A])
    header += (0x0001).to_bytes(2, "big")  # err=0, item count=1
    header += (0x0048).to_bytes(2, "big")  # mbz=0, item size=72
    return header + b"\x00" * 72           # one fake monitor entry


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        if VULN and is_mode7_monlist(data):
            s.sendto(build_monlist_response(), addr)
        # patched: ignore mode-7 (monlist disabled)


if __name__ == "__main__":
    main()
