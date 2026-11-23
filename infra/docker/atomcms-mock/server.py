#!/usr/bin/env python3
"""Mock Digital Craft AtomCMS server — CVE-2014-4852 (file upload + SQLi).

Vulnerable mode leaks the backend "UPDATE users SET avatar" statement from
/admin/uploads.php when the injectable `id` parameter is present, mirroring the
error-based SQL injection the OpenVAS NVT detects. Patched mode sanitises the
parameter and returns 404, producing zero findings.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ATOMCMS_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

LEAK = (
    "SQL syntax error near "
    "'UPDATE users SET avatar='avatar.php' WHERE id=1' — "
    "database(): ~'atomcms'~1"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Match the admin uploads endpoint with an injected `id` parameter.
        if self.path.startswith("/admin/uploads.php") and "id=" in self.path:
            if VULN_MODE:
                self._send(200, "<html><body>" + LEAK + "</body></html>")
            else:
                self._send(404, "<html><body>Not Found</body></html>")
        else:
            self._send(404, "<html><body>Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"),
                        os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(
            target=lambda: _make_https_server(PORT_HTTPS).serve_forever(),
            daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
