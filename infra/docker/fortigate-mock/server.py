#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("FORTIGATE_MODE", "patched") == "vuln"

LOGIN_HTML = b'<html class="main-app"><body>FortiOS Login</body></html>'

SW_JS = b'self.addEventListener(\'fetch\', function(event) { /* api/v2/static endpoint handler */ });'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/login":
            self._send(200, LOGIN_HTML)
        elif path == "/service-worker.js":
            if VULN_MODE:
                self._send(200, SW_JS, "application/javascript")
            else:
                body = b"Unauthorized"
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("WWW-Authenticate", "Bearer")
                self.end_headers()
                self.wfile.write(body)
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    mode = "vuln" if VULN_MODE else "patched"
    print(f"FortiGate mock on :80/:443 (mode={mode})", flush=True)
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
