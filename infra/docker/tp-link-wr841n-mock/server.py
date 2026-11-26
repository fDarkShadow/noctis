#!/usr/bin/env python3
"""Mock for CVE-2012-5687. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN = os.environ.get("CVE_2012_5687_MODE", "patched") == "vuln"


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
        if (path == '/'):
            self._start(401)
            self._h('WWW-Authenticate', 'Basic realm="TP-LINK Wireless N Router WR841N"')
            self._h('Content-Type', 'text/html')
            self._finish('<html><body>401 Authorization Required - TP-LINK TL-WR841N</body></html>\n')
            return
        if (vuln and 'etc/shadow' in path):
            self._start(200)
            self._h('Content-Type', 'application/octet-stream')
            self._finish('root:$1$xyz$abcdef0123456789:0:0:99999:7:::\ndaemon:*:1:1:99999:7:::\n')
            return
        if ('etc/shadow' in path):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish('<html><head><title>TP-LINK</title></head><body>The page cannot be displayed.</body></html>\n')
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
