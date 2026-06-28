#!/usr/bin/env python3
"""Mock Next.js server — CVE-2025-29927 (x-middleware-subrequest middleware bypass)."""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NEXTJS_MODE", "patched") == "vuln"

ADMIN_BODY = b"<html><body><h1>Admin Dashboard</h1><p>secret content</p></body></html>"
LOGIN_BODY = b"<html><body><h1>Login</h1></body></html>"
HOME_BODY = b"<html><body><h1>Home</h1></body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _has_bypass_header(self):
        subreq = self.headers.get("x-middleware-subrequest", "")
        return "middleware" in subreq

    def do_GET(self):
        if self.path.startswith("/admin"):
            if VULN_MODE and self._has_bypass_header():
                # Vulnerable: middleware skipped, protected content exposed
                self._send(200, ADMIN_BODY)
            else:
                # Auth required — redirect to login
                self._send(302, b"", extra_headers={"Location": "/login"})
        elif self.path.startswith("/login"):
            self._send(200, LOGIN_BODY)
        else:
            self._send(200, HOME_BODY)

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
    print(f"Next.js mock on :80/:443 (mode={mode})", flush=True)
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
