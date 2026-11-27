#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("EXPEDITION_MODE", "patched") == "vuln"

RESET_BODY = b"Admin user found\nAdmin password restored\nOperation completed"


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
        path = self.path.split("?")[0]
        if path == "/OS/startup/restore/restoreAdmin.php":
            if VULN_MODE:
                self._send(200, RESET_BODY)
            else:
                self._send(403, b"Access denied")
        else:
            self._send(404, b"Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
