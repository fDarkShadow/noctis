#!/usr/bin/env python3
"""Mock for Dragan Mitic Apoll admin/login.php SQL injection (CVE-2008-6270).

Vuln mode: a SQL-injection payload posted to /admin/login.php bypasses
authentication and the server redirects to the admin index with a
"Location: index.php" header. Patched mode: the login is rejected (401,
no redirect) so the detection pattern is absent → zero findings.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("APOLL_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("latin-1") if length else ""
        if self.path == "/admin/login.php":
            # A SQL-injection payload ("' or '1'='1") in the login fields
            # bypasses auth on a vulnerable install and redirects to index.php.
            if VULN_MODE and ("%271%27%3D%271" in body or "'1'='1" in body or "1'='1" in body):
                self._send(302, "", extra_headers={"Location": "index.php"})
            else:
                self._send(401, "Authentication required")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
