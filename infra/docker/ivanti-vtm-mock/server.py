#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

VULN_MODE = os.environ.get("IVANTI_VTM_MODE", "patched") == "vuln"

CREATED_USERS = {}

WIZARD_HTML = b'<html><body class="wizardtitletext">Ivanti vTM Setup Wizard - Create Admin User</body></html>'

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

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        params = parse_qs(raw.decode())
        path = urlparse(self.path).path

        if path == "/apps/zxtm/wizard.fcgi":
            if VULN_MODE:
                username = params.get("username", [""])[0]
                password1 = params.get("password1", [""])[0]
                password2 = params.get("password2", [""])[0]
                if username and password1 and password1 == password2:
                    CREATED_USERS[username] = password1
                    self._send(200, WIZARD_HTML)
                else:
                    self._send(400, b"Bad request")
            else:
                self.send_response(302)
                self.send_header("Location", "/apps/zxtm/login.cgi")
                self.send_header("Content-Length", "0")
                self.end_headers()

        elif path == "/apps/zxtm/login.cgi":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            if VULN_MODE and username in CREATED_USERS and CREATED_USERS.get(username) == password:
                self.send_response(302)
                self.send_header("Location", "/apps/zxtm/")
                self.send_header("Set-Cookie", "ZeusTMZAUTH=abcdef1234567890; Path=/apps/zxtm")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(200, b"<html><body>Login failed</body></html>")
        else:
            self._send(404, b"Not found")

    def do_GET(self):
        self._send(404, b"Not found")

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
