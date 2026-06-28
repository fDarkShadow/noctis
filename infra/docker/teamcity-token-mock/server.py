#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("TEAMCITY_MODE", "patched") == "vuln"

TOKEN_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<token name="RPC2" creationTime="2024-01-01T00:00:00.000Z"'
    b' value="eyABCDEFGHIJKLMNOP"/>'
)

TOKEN_PATH = "/app/rest/users/id:1/tokens/RPC2"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        if self.path == TOKEN_PATH:
            self._send(204, b"")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        if self.path == TOKEN_PATH:
            if VULN_MODE:
                self._send(200, TOKEN_XML, "application/xml; charset=UTF-8")
            else:
                self._send(401, b"Unauthorized")
        else:
            self._send(404, b"Not found")

    def do_GET(self):
        self._send(200, b"TeamCity", "text/html")


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
