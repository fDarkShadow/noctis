#!/usr/bin/env python3
"""Mock for CVE-2013-0632. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN = os.environ.get("CVE_2013_0632_MODE", "patched") == "vuln"


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
        if (vuln and method == 'POST' and path.startswith('/CFIDE/adminapi/administrator.cfc')):
            self._start(200)
            self._h('Content-Type', 'text/xml')
            self._h('Set-Cookie', 'CFAUTHORIZATION_cfadmin=xx-yy-zz; Path=/')
            self._finish("<wddxPacket version='1.0'><header/><data><boolean value='true'/></data></wddxPacket>\n")
            return
        if (vuln and path == '/CFIDE/administrator/homepage.cfm'):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish('<html><head><title>ColdFusion Administrator Home Page</title></head><body>Welcome to the ColdFusion Administrator</body></html>\n')
            return
        if (method == 'POST' and path.startswith('/CFIDE/adminapi/administrator.cfc')):
            self._start(200)
            self._h('Content-Type', 'text/xml')
            self._finish("<wddxPacket version='1.0'><header/><data><boolean value='false'/></data></wddxPacket>\n")
            return
        if (path == '/CFIDE/administrator/homepage.cfm'):
            self._start(401)
            self._h('Content-Type', 'text/html')
            self._h('WWW-Authenticate', 'Basic realm="ColdFusion Administrator"')
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
