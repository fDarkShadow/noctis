#!/usr/bin/env python3
"""Mock for Apache Axis2 admin console (CVE-2010-0219 — default credentials).

Vuln mode: POST /axis2-admin/login with the default credentials
(admin / axis2) succeeds and the server issues a JSESSIONID session cookie.
Patched mode: the default credentials are rejected (403, no session cookie).
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("AXIS2_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

LOGIN_PAGE = (
    "<html><head><title>Axis2 :: Administration</title></head>"
    "<body><form method=\"post\" action=\"login\">"
    "<input name=\"userName\"><input name=\"password\" type=\"password\">"
    "<input type=\"submit\" name=\"submit\"></form></body></html>"
)
ADMIN_PAGE = (
    "<html><head><title>Axis2 :: Administration Page</title></head>"
    "<body><h1>Welcome to Axis2 Web Admin Module !!</h1>"
    "<a href=\"upload\">Upload Service</a></body></html>"
)


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            return self.rfile.read(length).decode("latin-1")
        return ""

    def do_POST(self):
        if self.path == "/axis2-admin/login":
            body = self._read_body()
            default_creds = "userName=admin" in body and "password=axis2" in body
            if VULN_MODE and default_creds:
                # Successful login → authenticated session cookie issued.
                self._send(
                    200,
                    ADMIN_PAGE,
                    extra_headers={"Set-Cookie": "JSESSIONID=A1B2C3D4E5F6A7B8C9D0E1F2; Path=/axis2"},
                )
            else:
                # Default creds rejected: re-show the login form, no session cookie.
                self._send(403, LOGIN_PAGE)
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/axis2-admin/login":
            self._send(200, LOGIN_PAGE)
        else:
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
