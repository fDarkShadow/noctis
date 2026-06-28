#!/usr/bin/env python3
"""Mock PAN-OS ZTP management interface — CVE-2024-0012 (auth bypass via X-PAN-AUTHCHECK)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PANOS_ZTP_MODE", "patched") == "vuln"

# Realistic ZTP source-map response — matches both patterns in the feed:
#   "Zero Touch Provisioning" and "mainui\.javascript"
VULN_BODY = (
    '{"version":3,"sources":["mainui.javascript"],'
    '"mappings":"AAAA","names":[],'
    '"x-comment":"Zero Touch Provisioning management plane"}'
)


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
        if self.path == "/php/ztp_gate.php/.js.map":
            if VULN_MODE and self.headers.get("X-PAN-AUTHCHECK", "").lower() == "off":
                self._send(200, VULN_BODY, ct="application/json")
            else:
                # Patched: auth middleware ignores the bypass header
                self._send(302, "Redirecting", ct="text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
