#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NETSCALER_MODE", "patched") == "vuln"

# Vuln: NSC_TASS cookie base64-decodes to "wctx=123456" (contains wctx=)
# d2N0eD0xMjM0NTY= is base64("wctx=123456")
VULN_COOKIE = "d2N0eD0xMjM0NTY="
# Patched: NSC_TASS base64-decodes to "hello" (no wctx=)
PATCHED_COOKIE = "aGVsbG8="

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)

        if self.path.startswith("/saml/login"):
            nsc_cookie = VULN_COOKIE if VULN_MODE else PATCHED_COOKIE
            self._send(302, b"", extra_headers={
                "Location": "/cgi/samlauth?SAMLResponse=placeholder",
                "Set-Cookie": f"NSC_TASS={nsc_cookie}; path=/; HttpOnly; SameSite=Strict",
            })
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/":
            self._send(200, "<html><body>NetScaler Gateway</body></html>")
        else:
            self._send(404, "Not found")

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
