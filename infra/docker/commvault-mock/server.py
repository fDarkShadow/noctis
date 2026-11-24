#!/usr/bin/env python3
import os, ssl, threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("COMMVAULT_MODE", "patched") == "vuln"

ERROR_BODY = b'{"error":"Invalid commcell"}'
FORBIDDEN = b'{"error":"Forbidden"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/commandcenter/deployWebpackage.do":
            self._send(404, b'{"error":"Not found"}')
            return
        if not VULN_MODE:
            self._send(403, FORBIDDEN)
            return
        raw = self._read_body()
        params = parse_qs(raw.decode(errors="replace"))
        commcell = params.get("commcellName", [""])[0]
        if commcell.startswith("http://") or commcell.startswith("https://"):
            try:
                urllib.request.urlopen(commcell, timeout=5)
            except Exception:
                pass
        self._send(900, ERROR_BODY)

    def do_GET(self):
        self._send(404, b'{"error":"Not found"}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
