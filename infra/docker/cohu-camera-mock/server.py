#!/usr/bin/env python3
"""Mock for CVE-2017-8860 — Cohu 3960HD Multiple Vulnerabilities (CVSS 10.0).
Ported from OpenVAS/Greenbone NASL 2017/gb_cohu_camera_mult_vuln.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CVE_2017_8860_MODE", "patched") == "vuln"

MARKER_BODY = '<html><body><h1>Directory listing of //</h1></body></html>\n'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send_marker(self):
        body = MARKER_BODY.encode("latin-1", "replace")
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self):
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "10")
        self.end_headers()
        self.wfile.write(b"Not found\n")

    def do_GET(self):
        if VULN_MODE and (self.path in ('/', '//')):
            self._send_marker()
        else:
            self._not_found()

    def do_POST(self):
        self.do_GET()


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
