#!/usr/bin/env python3
"""Mock for CVE-2013-3316. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN = os.environ.get("CVE_2013_3316_MODE", "patched") == "vuln"


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
        if (vuln and (path.startswith('/NETGEAR_fwpt.cfg'))):
            self._start(200)
            self._h('Content-Type', 'application/configuration')
            self._h('Server', 'NETGEAR')
            self._finish('NETGEAR WNR1000v3 config\n')
            return
        if (path.startswith('/NETGEAR_fwpt.cfg')):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish("<html><head><title>NETGEAR WNR1000v3 'Image' Request Authentication Bypass Vulnerability</title></head><body><h1>Welcome</h1><p>Please sign in to continue.</p><form method=post action=/login><input name=user><input name=pass type=password></form></body></html>\n")
            return
        # default
        self._start(404)
        self._h("Content-Type", "text/plain")
        self._finish("Not found\n")

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


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
