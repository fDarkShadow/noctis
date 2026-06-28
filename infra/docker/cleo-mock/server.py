#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CLEO_MODE", "patched") == "vuln"

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

    def do_GET(self):
        if self.path.startswith("/Synchrony/"):
            if VULN_MODE:
                body = (
                    "<html><title>Cleo Harmony</title>"
                    "<body>NOCTIS_CLEO_VULN<br/>Version: 5.8.0.21</body></html>"
                )
                self._send(200, body)
            else:
                self._send(
                    401, b"",
                    extra_headers={"WWW-Authenticate": 'Basic realm="Cleo Harmony"'}
                )
        else:
            self._send(200, "<html><title>Cleo Harmony — Login</title></html>")

    def do_POST(self):
        if self.path.startswith("/Synchrony/"):
            if VULN_MODE:
                self._send(200, '{"status":"uploaded","file":"test.xml"}', ct="application/json")
            else:
                self._send(
                    401, b"",
                    extra_headers={"WWW-Authenticate": 'Basic realm="Cleo Harmony"'}
                )
        else:
            self._send(404, "Not Found")

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
