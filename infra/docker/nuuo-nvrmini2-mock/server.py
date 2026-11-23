#!/usr/bin/env python3
"""Mock for CVE-2018-11523 — NUUO NVRmini 2 < 3.9.1 File Upload RCE (CVSS 7.5).
Ported from OpenVAS/Greenbone NASL 2018/nuuo/gb_nuuo_nvrmini2_file_upload_vuln.nasl
(GPL-2.0-only, Greenbone Community Feed).

Vuln mode: POST / uploads+executes a PHP file, returning a phpinfo() page that
contains "PHP Version" and "PHP API", confirming RCE.
Patched mode: POST / returns 404 without that content -> zero findings."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NVRMINI2_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

PHPINFO = (
    "<html><head><title>phpinfo()</title></head><body>"
    "<h1>PHP Version 5.4.16</h1>"
    "<table><tr><td>System</td><td>Linux nvrmini2 3.10.0</td></tr>"
    "<tr><td>Server API</td><td>CGI/FastCGI</td></tr>"
    "<tr><td>PHP API</td><td>20100412</td></tr>"
    "<tr><td>Zend Extension Build</td><td>API220100525</td></tr>"
    "</table></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n:
            self.rfile.read(n)

    def do_POST(self):
        self._drain()
        if VULN_MODE and self.path == "/":
            self._send(200, PHPINFO)
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
