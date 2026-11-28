#!/usr/bin/env python3
# Mock for CVE-2017-7921 — Hikvision authentication bypass.
#
# The magic query parameter auth=YWRtaW46MTEK (base64 of a hardcoded exploit
# string) bypasses authentication on /system/deviceInfo.
#
#   vuln     : /system/deviceInfo WITH the magic auth param → 200 + application/xml
#              device info, echoing the caller's ?probe= nonce. WITHOUT it → 401
#              (the auth check still applies to ordinary requests — this is the
#              negative control that defeats a blanket-200 cheat).
#   patched  : /system/deviceInfo → 401 regardless of the magic param.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("HIKVISION_MODE", "patched") == "vuln"
MAGIC = "YWRtaW46MTEK"  # public exploit constant, not a real credential


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/system/deviceInfo":
            qs = parse_qs(parts.query)
            has_magic = MAGIC in qs.get("auth", [])
            if VULN_MODE and has_magic:
                # Reflect the caller's nonce so a constant/unrelated response
                # cannot satisfy the scanner's match.
                nonce = (qs.get("probe", [""])[0]) or ""
                xml = (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema">\n'
                    '<deviceName>NOCTIS_HIKVISION_CONFIRMED</deviceName>\n'
                    '<deviceID>' + nonce + '</deviceID>\n'
                    '<model>DS-2CD2032-I</model>\n'
                    '<serialNumber>DS-NOCTIS0120170007921</serialNumber>\n'
                    '<firmwareVersion>V5.4.0</firmwareVersion>\n'
                    '<firmwareReleasedDate>build 160530</firmwareReleasedDate>\n'
                    '</DeviceInfo>\n'
                )
                self._send(200, xml, ct="application/xml")
            else:
                # Patched device, or vuln device without the magic param.
                self._send(401, "Unauthorized")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
