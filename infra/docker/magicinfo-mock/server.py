#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("MAGICINFO_MODE", "patched") == "vuln"

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
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        if path == "/MagicInfo/noctis_probe.jsp":
            if VULN_MODE:
                noctis_val = params.get("noctis", [""])[0]
                self._send(200, noctis_val if noctis_val else "executed")
            else:
                self._send(404, "Not Found")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if path == "/MagicInfo/servlet/SWUpdateFileUploader":
            if VULN_MODE:
                self._send(200, "Upload accepted")
            else:
                self._send(403, "Access denied")
        else:
            self._send(404, "Not Found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
