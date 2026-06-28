#!/usr/bin/env python3
"""Mock Citrix NetScaler ADC/Gateway server — CVE-2023-4966 (Citrix Bleed heap over-read)."""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NETSCALER_MODE", "patched") == "vuln"

OPENID_JSON = (
    b'{"issuer":"https://netscaler/oauth/idp",'
    b'"authorization_endpoint":"https://netscaler/oauth/idp/login",'
    b'"token_endpoint":"https://netscaler/oauth/idp/token",'
    b'"jwks_uri":"https://netscaler/oauth/idp/certs",'
    b'"response_types_supported":["code"],'
    b'"subject_types_supported":["public"],'
    b'"id_token_signing_alg_values_supported":["RS256"]}'
)

# Simulated heap leak: 100 lowercase hex chars + NSC_AAAC token terminator marker.
# Matches regex [a-f0-9]{100}45525d5f4f58455e445a4a42 as documented by Assetnote.
LEAK_MARKER = b"aa" * 50 + b"45525d5f4f58455e445a4a42"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/oauth/idp/.well-known/openid-configuration":
            host = self.headers.get("Host", "")
            if VULN_MODE and len(host) > 1000:
                # Simulate heap bleed: append leaked session token bytes after JSON
                body = OPENID_JSON + b" " + LEAK_MARKER
            else:
                body = OPENID_JSON
            self._send(200, body)
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        self._send(405, b'{"error":"method not allowed"}')


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    print(f"NetScaler mock on :80/:443 (mode={mode})", flush=True)
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
