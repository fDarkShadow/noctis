#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PANOS_MODE", "patched") == "vuln"

ZTP_BODY = (
    "<html><head><title>Zero Touch Provisioning (ZTP)</title></head>"
    "<body><script src=\"/scripts/cache/mainui.javascript\"></script>"
    "<p>PAN-OS ZTP Interface</p></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/php/ztp_gate.php/.js.map":
            authcheck = self.headers.get("X-PAN-AUTHCHECK", "")
            if VULN_MODE and authcheck.lower() == "off":
                self._send(
                    200, ZTP_BODY,
                    headers={"Set-Cookie": "PHPSESSID=abcdef123456789; Path=/; Secure"}
                )
            else:
                self._send(302, "Found", headers={"Location": "/php/login.php"})
        elif self.path == "/php/login.php":
            self._send(200, "<html><body><title>PAN-OS</title><p>Login</p></body></html>")
        elif self.path == "/":
            self._send(302, "Found", headers={"Location": "/php/login.php"})
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
