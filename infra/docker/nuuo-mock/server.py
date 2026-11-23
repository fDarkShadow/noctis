#!/usr/bin/env python3
"""Mock for NUUO NVR devices — shared across multiple CVEs.

Consumers:
  * CVE-2018-1150 — NVRMini2 backdoor, unauthenticated account disclosure via
    GET /users_xml.php.
    Ported from OpenVAS NASL 2018/nuuo/gb_nuuo_nvr_backdoor_active.nasl (GPL-2.0-only).
  * CVE-2016-6553 — NUUO NVR default credentials. POST /login.php with known
    default creds returns a PHPSESSID session cookie.
    Ported from OpenVAS NASL 2016/gb_nuuo_devices_default_http_login.nasl (GPL-2.0-only).

Each endpoint is an independent branch — do not change one when editing another.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NUUO_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def do_GET(self):
        # CVE-2018-1150 — backdoor account disclosure
        if VULN_MODE and self.path == "/users_xml.php":
            xml = ("<Response><AccountInfo>"
                   "<User><Name>guest</Name><Privilege>1</Privilege></User>"
                   "<User><Name>operator</Name><Privilege>2</Privilege></User>"
                   "</AccountInfo></Response>")
            self._send(200, xml, ct="text/xml")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        # CVE-2016-6553 — default credentials on the NVR web login
        if self.path == "/login.php":
            self._body()
            if VULN_MODE:
                # Successful login with default creds issues a PHP session cookie.
                self._send(200, "<html><body>Welcome</body></html>",
                           ct="text/html",
                           extra_headers={"Set-Cookie": "PHPSESSID=5f3a9c1b2d4e6f8a0b1c2d3e; path=/"})
            else:
                # Patched: default creds rejected, no session established.
                self._send(401, "<html><body>Login failed</body></html>", ct="text/html")
        else:
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
