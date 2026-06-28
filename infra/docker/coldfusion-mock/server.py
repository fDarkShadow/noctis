#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("COLDFUSION_MODE", "patched") == "vuln"

# tcp_connect sends the raw path, and Python's BaseHTTPRequestHandler sets
# self.path to the un-normalised request URI. The traversal marker ..CFIDE
# arrives intact (Python does not resolve .. in self.path).
TRAVERSAL_MARKER = "..CFIDE"

WDDX_RESPONSE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<wddxPacket version="1.0">'
    "<header/>"
    "<data><string>NOCTIS_CF_HEARTBEAT_OK</string></data>"
    "</wddxPacket>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if TRAVERSAL_MARKER in self.path:
            if VULN_MODE:
                self._send(200, WDDX_RESPONSE, ct="text/xml")
            else:
                self._send(403, "Access denied")
        else:
            self._send(
                200,
                "<html><head><title>Adobe ColdFusion Administrator</title></head>"
                "<body><h1>ColdFusion</h1></body></html>",
            )

    def do_POST(self):
        self.do_GET()


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
