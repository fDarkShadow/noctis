#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SONICWALL_SMA_MODE", "patched") == "vuln"

VULN_BODY = (
    b"<html><head><title>Appliance Management Console</title></head>"
    b"<body><h1>SMA 1000 - Appliance Management Console</h1>"
    b"<p>Version 12.4.3.02804</p></body></html>"
)
PATCHED_BODY = (
    b"<html><head><title>Appliance Management Console</title></head>"
    b"<body><h1>SMA 1000 - Appliance Management Console</h1>"
    b"<p>Version 12.4.3.02900</p></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", location=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(302, b"", location="/appliance/login")
        elif path == "/appliance/login":
            body = VULN_BODY if VULN_MODE else PATCHED_BODY
            self._send(200, body)
        else:
            self._send(404, b"Not found")

    def do_POST(self):
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
