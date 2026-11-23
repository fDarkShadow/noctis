#!/usr/bin/env python3
"""Mock for CVE-2025-34126 — RIPS Scanner 0.55 Multiple LFI Vulnerabilities (CVSS 7.8).
Ported from OpenVAS/Greenbone NASL 2016/gb_rips_lfi_vuln.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CVE_2025_34126_MODE", "patched") == "vuln"

MARKER_BODY = '<b>securing functions</b> defined in ./config/securing.php\n'


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
        if VULN_MODE and (self.path.startswith('/windows/function.php')):
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
