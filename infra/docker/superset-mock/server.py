#!/usr/bin/env python3
"""Mock Apache Superset server — CVE-2023-27524 (default SECRET_KEY session forgery)."""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SUPERSET_MODE", "patched") == "vuln"

KNOWN_DEFAULT_SESSIONS = {
    "eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFnng.XPeCvkBiP7rOv1PhgKZ8xkzi2jk",
    "eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFq1Q.7j3T2W6yz_Uq_7I0fZNqv7w7ASk",
    "eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFsLg.X0RW2K7zQJ-b5O_lK4kO5vN1kOM",
    "eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFt0Q.yH8k9nNL_Q0pZ3v4X2w7K8m5YoE",
    "eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFuSg.d4nPz5Xk3Q2mR7wL1v9T8h6Y0cU",
}

DB_RESPONSE = b'{"id":1,"database_name":"examples","sqlalchemy_uri":"sqlite:///:memory:","expose_in_sqllab":true,"allow_run_async":false}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _has_default_session(self):
        cookie_header = self.headers.get("Cookie", "")
        for token in KNOWN_DEFAULT_SESSIONS:
            if token in cookie_header:
                return True
        return False

    def do_GET(self):
        if self.path == "/api/v1/database/1":
            if VULN_MODE and self._has_default_session():
                self._send(200, DB_RESPONSE)
            else:
                self._send(401, b'{"message":"Please log in to access this page."}')
        elif self.path == "/health":
            self._send(200, b'"OK"')
        else:
            self._send(404, b'{"message":"Not found"}')

    def do_POST(self):
        self.do_GET()


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
    print(f"Superset mock on :80/:443 (mode={mode})", flush=True)
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
