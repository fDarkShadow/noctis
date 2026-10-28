#!/usr/bin/env python3
"""Minimal SNMP v2c GET responder for the default-community check (no pysnmp dep).

vuln:    answers a GET with ANY community (including the defaults public/private),
         returning a sysDescr string.
patched: answers only the non-default community $SNMP_COMMUNITY, so public/private
         get no reply and the client times out.

Only enough BER to echo the request's version/community/request-id/OIDs back in a
GetResponse — this is test scaffolding, not a general SNMP stack.
"""
import os
import socket

VULN = os.environ.get("SNMP_MODE", "patched") == "vuln"
PORT = int(os.environ.get("SNMP_PORT", "161"))
SECRET = os.environ.get("SNMP_COMMUNITY", "s3cr3t")
SYSDESCR = b"Noctis SNMP mock - RouterOS 6.40.5"


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = []
    while n > 0:
        b.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(b)]) + bytes(b)


def tlv(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def read_tlv(buf, i):
    tag = buf[i]
    first = buf[i + 1]
    if first < 0x80:
        ln, j = first, i + 2
    else:
        nb = first & 0x7F
        ln = int.from_bytes(buf[i + 2:i + 2 + nb], "big")
        j = i + 2 + nb
    return tag, buf[j:j + ln], j + ln


def parse_request(data):
    _, seq, _ = read_tlv(data, 0)              # outer SEQUENCE
    i = 0
    vtag, vcontent, i = read_tlv(seq, i)        # version INTEGER
    version_raw = tlv(vtag, vcontent)
    ctag, ccontent, i = read_tlv(seq, i)        # community OCTET STRING
    community = ccontent.decode("latin1")
    community_raw = tlv(ctag, ccontent)
    _ptag, pcontent, _ = read_tlv(seq, i)       # PDU (0xA0 GetRequest)
    j = 0
    rtag, rcontent, j = read_tlv(pcontent, j)   # request-id
    reqid_raw = tlv(rtag, rcontent)
    _etag, _ec, j = read_tlv(pcontent, j)       # error-status
    _e2, _e2c, j = read_tlv(pcontent, j)        # error-index
    _vbltag, vbl, j = read_tlv(pcontent, j)     # varbind list SEQUENCE
    oids = []
    k = 0
    while k < len(vbl):
        _vbtag, vbcontent, k = read_tlv(vbl, k)  # varbind SEQUENCE
        otag, ocontent, _ = read_tlv(vbcontent, 0)  # OID
        oids.append(tlv(otag, ocontent))
    return version_raw, community, community_raw, reqid_raw, oids


def build_response(version_raw, community_raw, reqid_raw, oids):
    varbinds = b""
    for oid_raw in oids:
        varbinds += tlv(0x30, oid_raw + tlv(0x04, SYSDESCR))
    zero = tlv(0x02, b"\x00")
    pdu = tlv(0xA2, reqid_raw + zero + zero + tlv(0x30, varbinds))  # GetResponse
    return tlv(0x30, version_raw + community_raw + pdu)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", PORT))
    while True:
        data, addr = s.recvfrom(65535)
        try:
            version_raw, community, community_raw, reqid_raw, oids = parse_request(data)
        except Exception:
            continue
        if not (VULN or community == SECRET):
            continue  # default community on a patched agent → silent (timeout)
        s.sendto(build_response(version_raw, community_raw, reqid_raw, oids), addr)


if __name__ == "__main__":
    main()
