#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

VULN_MODE = os.environ.get("CRAFT_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)
        if "generate-transform" in parsed.query or "generate-transform" in parsed.path:
            if VULN_MODE:
                self._send(200, '{"error":"NOCTIS_CRAFT_VULN","version":"5.6.10"}')
            else:
                self._send(400, '{"message":"Bad Request","error":"Not Found"}')
        else:
            self._send(404, '{"error":"Not Found"}')

    def do_GET(self):
        if self.path.startswith("/admin/"):
            self._send(200, "<html><title>Craft CMS — Dashboard</title></html>", ct="text/html")
        else:
            self._send(200, "<html><title>Craft CMS</title></html>", ct="text/html")

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
