#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("MANAGEENGINE_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def do_GET(self):
        if self.path.startswith("/SamlResponseServlet") or self.path.startswith("/samlLogin"):
            html = "<html><body>ManageEngine ServiceDesk Plus — SAML SSO</body></html>"
            self._send(200, html)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self._read_body()
        if self.path.startswith("/SamlResponseServlet"):
            if VULN_MODE:
                error = "Unknown error occurred while processing your request"
                self._send(500, error, "text/plain")
            else:
                self._send(400, "Invalid SAML request", "text/plain")
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
