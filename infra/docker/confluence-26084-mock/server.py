#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CONFLUENCE_26084_MODE", "patched") == "vuln"


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        self._send(404, "Not found")

    def do_POST(self):
        self._read_body()
        if self.path.startswith("/pages/doenterpagevariables.action"):
            if VULN_MODE:
                self._send(200, "NOCTIS_CONF_OGNL_CONFIRMED", "text/html")
            else:
                self._send(400, "Bad Request")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
