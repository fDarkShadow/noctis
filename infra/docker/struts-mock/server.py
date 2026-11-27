#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("STRUTS_MODE", "patched") == "vuln"

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

    def do_POST(self):
        if self.path == "/upload.action":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

            # Check if filename contains path traversal
            m = re.search(r'filename="([^"]*)"', raw)
            filename = m.group(1) if m else ""
            has_traversal = ".." in filename

            if VULN_MODE and has_traversal:
                self._send(200, "NOCTIS_STRUTS_RCE_CONFIRMED")
            elif VULN_MODE:
                self._send(200, "File uploaded successfully")
            else:
                self._send(400, "Invalid file name: path traversal detected")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
