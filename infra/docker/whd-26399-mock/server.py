#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WHD_MODE", "patched") == "vuln"

LOGIN_BODY = (
    b"<html><title>Web Help Desk - SolarWinds</title>"
    b"<body>Web Help Desk Login</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/helpdesk/" or path == "/helpdesk":
            self.send_response(302)
            self.send_header("Location", "/helpdesk/login")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/helpdesk/login":
            self._send(200, LOGIN_BODY)
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        self._read_body()
        path = self.path.split("?")[0]
        if path == "/helpdesk/AjaxProxy":
            if VULN_MODE:
                self._send(500,
                           "java.io.StreamCorruptedException: invalid stream header: 41434544",
                           "text/plain")
            else:
                self._send(404, b"Not Found")
        else:
            self._send(404, b"Not Found")


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
