#!/usr/bin/env python3
"""Mock for CVE-2021-27850. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
Both modes redirect the asset dir to the hashed class URL; only vuln serves the class at
<loc>/ (the trailing-slash form the NASL requests), while patched 404s it — a non-trivial TN
that exercises the real Tapestry fix (redirect stays, class download is refused)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN = os.environ.get("CVE_2021_27850_MODE", "patched") == "vuln"


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
        # Step 1: the unhashed asset dir redirects to the hashed class URL in BOTH modes, as a
        # real Tapestry does (the redirect alone does not prove the vulnerability).
        if path == '/assets/app/something/services/AppModule.class/':
            self._start(302)
            self._h('Location', '/assets/meta/AppModule.class')
            self._h('Content-Type', 'text/html')
            self._finish('<html><body>Found</body></html>\n')
            return
        # Step 2: the NASL follows <loc> with a trailing slash. Only a vulnerable build serves
        # the compiled class there; a patched build refuses it.
        if vuln and path == '/assets/meta/AppModule.class/':
            self._start(200)
            self._h('Content-Type', 'application/java')
            self._finish('\xca\xfe\xba\xbe\x00\x00AppModule$InnerClasses SignatureAttribute\n')
            return
        if path == '/assets/meta/AppModule.class/':
            self._start(404)
            self._h('Content-Type', 'text/plain')
            self._finish('Not found\n')
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
