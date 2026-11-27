#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve   # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("FORTIOS_MODE", "patched") == "vuln"

# Normal FortiOS SSL VPN language endpoint response (what a valid ?lang= returns).
FGT_LANG_JS = b"var fgt_lang = {\n  \"sslvpn_login\": \"SSL-VPN Login\"\n};\n"

# Realistic /dev/cmdb/sslvpn_websession record: a small count/header, then one
# session record whose layout is a null-padded username field followed by the
# recorded client source IPv4 and the SSL-VPN portal name. This mirrors the
# structure a real vulnerable FortiGate leaks — the detection matches the generic
# null-framed-username + client-IP layout, not any mock-specific marker.
SSLVPN_WEBSESSION = (
    b"\x07\x00\x00\x00"
    b"\x01\x00\x00\x00"
    + b"jdoe" + b"\x00" * 12
    + b"192.168.10.45" + b"\x00" * 3
    + b"full-access" + b"\x00" * 5
    + b"\x00" * 16
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path is the raw request target — http.server does not normalise ../
        if self.path.startswith("/remote/fgt_lang"):
            if "sslvpn_websession" in self.path:
                if VULN_MODE:
                    # Traversal escapes the language dir and reads the session store.
                    self._send(200, SSLVPN_WEBSESSION, "application/octet-stream")
                else:
                    # Patched: lang parameter is sanitised, traversal is rejected.
                    self._send(403, "Permission denied.")
            else:
                # Benign language request — identical on both variants.
                self._send(200, FGT_LANG_JS, "application/javascript")
        elif self.path.startswith("/remote/login"):
            self._send(200, "<html><body>SSL-VPN Login</body></html>")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
