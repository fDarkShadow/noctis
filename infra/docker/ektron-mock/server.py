#!/usr/bin/env python3
# Mock for Ektron CMS < 8.02 SP5 RCE — CVE-2012-5357
# Vuln mode: /WorkArea/ContentDesigner/ekajaxtransform.aspx reflects the output
#   of an attacker-supplied XSLT/JScript command (ipconfig) — "Windows IP Configuration".
# Patched mode: the endpoint returns 404 (no RCE, zero findings).
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EKTRON_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

IPCONFIG_OUTPUT = (
    "\r\nWindows IP Configuration\r\n\r\n"
    "Ethernet adapter Local Area Connection:\r\n\r\n"
    "   Connection-specific DNS Suffix  . :\r\n"
    "   IPv4 Address. . . . . . . . . . . : 10.0.0.5\r\n"
    "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
    "   Default Gateway . . . . . . . . . : 10.0.0.1\r\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        if self.path == "/WorkArea/ContentDesigner/ekajaxtransform.aspx":
            if VULN_MODE:
                self._send(200, IPCONFIG_OUTPUT)
            else:
                self._send(404, "Not found")
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
