#!/usr/bin/env python3
# Mock for Pandora FMS < 5.1 SP1 Multiple Vulnerabilities (CVE-2014-125115).
# Vuln mode: POST /mobile/index.php returns the mobile console login markup,
# whose form field markup matches the NASL content pattern `input([0-9a-z]+).*id`.
# Patched mode: the mobile console is disabled -> benign body, pattern absent.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PANDORA_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Mobile console login page rendered by vulnerable Pandora FMS. The login form
# markup is emitted on a single line so the NASL regex `input([0-9a-z]+).*id`
# matches it (Rust regex `.` does not span newlines).
VULN_BODY = (
    "<!DOCTYPE html><html><head><title>Pandora FMS Mobile</title></head>\n"
    "<body data-role=\"page\">\n"
    "<div data-role=\"content\" class=\"login\">\n"
    "<form action=\"index.php\" method=\"post\">\n"
    "<li class=\"input1field\" id=\"login_user_id\">User</li>\n"
    "<input type=\"password\" name=\"pass\">\n"
    "</form></div></body></html>\n"
)

PATCHED_BODY = (
    "<!DOCTYPE html><html><head><title>Pandora FMS</title></head>\n"
    "<body>Pandora FMS mobile console is disabled.</body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/mobile/index.php":
            if VULN_MODE:
                self._send(200, VULN_BODY)
            else:
                self._send(200, PATCHED_BODY)
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
