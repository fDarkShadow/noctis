#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SIMPLEHELP_MODE", "patched") == "vuln"

TRAVERSAL_PATH = "/toolbox-resource/../serverconfig.xml"

# CVE-2026-48558 — vuln = 5.5.15 with OIDC technician login configured,
# patched = 5.5.17 (no OIDC discovery document).
VERSION = "5.5.15" if VULN_MODE else "5.5.17"
OIDC_PATH = "/.well-known/openid-configuration"
OIDC_CONFIG = (
    '{"issuer":"https://auth.example.com",'
    '"authorization_endpoint":"https://auth.example.com/auth",'
    '"token_endpoint":"https://auth.example.com/token",'
    '"NOCTIS_SIMPLEHELP_OIDC":"configured"}'
)

CONFIG_XML = (
    "<SimpleSuite><Settings>"
    "<HashPassword>noctis_hash_AAAA1234</HashPassword>"
    "<AdminUser>admin</AdminUser>"
    "</Settings></SimpleSuite>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == TRAVERSAL_PATH:
            if VULN_MODE:
                self._send(200, CONFIG_XML, "application/octet-stream")
            else:
                self._send(403, "Forbidden")
        elif self.path == "/":
            self._send(200, f"SimpleHelp {VERSION} - Technician Login", "text/html")
        elif self.path == OIDC_PATH and VULN_MODE:
            self._send(200, OIDC_CONFIG, "application/json")
        else:
            self._send(404, "Not Found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
