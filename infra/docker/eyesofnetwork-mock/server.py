#!/usr/bin/env python3
"""Mock for CVE-2020-8656 — EyesOfNetwork (CVSS 7.5)
Ported from OpenVAS NASL 2020/eyesofnetwork/gb_eyesofnetwork_api_vuln_active.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EYESOFNETWORK_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def do_GET(self):
        if self.path.startswith("/eonapi/getApiKey"):
            if VULN_MODE and "union" in self.path.lower():
                self._send(200, '{"http_code": "200 OK", "EONAPI_KEY": "1c85d47ff80b5ff2a4dd577e8e5f8e9d"}', ct="application/json")
            else:
                self._send(200, '{"http_code": "401 Unauthorized", "error": "Invalid credentials"}', ct="application/json")
        else:
            self._send(404, "Not found")

    def do_POST(self):
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
