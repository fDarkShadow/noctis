#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("LOADMASTER_MODE", "patched") == "vuln"

VULN_BODY = (
    "WWW-Authenticate: Basic realm=\"LoadMaster\"\n"
    "bin\nboot\ndev\netc\nhome\nlib\nmnt\nproc\ntmp\nusr\nvar\n"
)

PATCHED_BODY = "WWW-Authenticate: Basic realm=\"LoadMaster\"\n"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/access/set"):
            if VULN_MODE:
                self._send(200, VULN_BODY)
            else:
                self._send(401, PATCHED_BODY)
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
