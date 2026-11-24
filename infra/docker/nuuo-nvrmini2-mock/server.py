#!/usr/bin/env python3
"""Mock for CVE-2011-5325. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN = os.environ.get("CVE_2011_5325_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _start(self, code):
        self._body = b""
        self._code = code
        self._hdrs = []

    def _h(self, k, v):
        self._hdrs.append((k, v))

    def _finish(self, body):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        self.send_response(self._code)
        for k, v in self._hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("latin-1", "replace") if n else ""

    def _route(self, method):
        path = self.path
        body = self._read_body()
        vuln = VULN
        cookie = self.headers.get("Cookie", "")
        if (vuln and (path == '/handle_import_user.php')):
            self._start(200)
            self._finish('There was an error uploading the file\n')
            return
        if (path == '/handle_import_user.php'):
            self._start(401)
            self._h('WWW-Authenticate', 'Basic realm="NUUO NVRmini2"')
            self._h('Content-Type', 'text/html')
            self._finish('<html><body>401 Authorization Required</body></html>\n')
            return
        # default
        self._start(404)
        self._h("Content-Type", "text/plain")
        self._finish("Not found\n")

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
