#!/usr/bin/env python3
"""Mock for Open Web Analytics < 1.5.5 password-reset SQL injection (CVE-2014-1206).

Vuln mode: POST /index.php?owa_do=base.passwordResetForm echoes the submitted
e-mail address back inside an "Invalid address:" SQL error, confirming the SQLi.
Patched mode: the same endpoint returns a benign 200 without reflecting the marker.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VULN_MODE = os.environ.get("OWA_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

RESET_PATH = "/index.php?owa_do=base.passwordResetForm"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == RESET_PATH:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            params = parse_qs(raw)
            email = (params.get("owa_email_address[passwordResetForm]") or [""])[0]
            if VULN_MODE:
                # Vulnerable build reflects the e-mail into the SQL error message.
                self._send(
                    200,
                    "<html><body>Invalid address: %s</body></html>" % email,
                )
            else:
                # Patched build validates the address and never reflects it.
                self._send(
                    200,
                    "<html><body>If that address exists a reset email has been sent.</body></html>",
                )
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
