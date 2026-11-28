#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("BUFFALO_MODE", "patched") == "vuln"

# The device information page. On a real Arcadyan/Buffalo device this is served
# only after authentication; the traversal bug exposes it unauthenticated.
INFO_PAGE = (
    "<html><head><title>Device Information</title></head>"
    "<body><h1>Device Information</h1>"
    "<table>"
    "<tr><td>Model</td><td>WSR-2533DHPL2</td></tr>"
    "<tr><td>Firmware</td><td>1.02</td></tr>"
    "<tr><td>LAN MAC</td><td>00:11:22:33:44:55</td></tr>"
    "<tr><td>WAN IP</td><td>192.0.2.10</td></tr>"
    "</table></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # The protected page is always behind authentication when asked for
        # directly, on both vulnerable and patched firmware.
        if self.path == "/info.html":
            self._send(401, "Unauthorized")
            return

        # The traversal: /images/<anything>/..%2finfo.html . Only vulnerable
        # firmware resolves this to the protected page and serves it unauth;
        # patched firmware rejects the traversal.
        if self.path.startswith("/images/") and self.path.endswith("info.html") and "..%2f" in self.path:
            if VULN_MODE:
                self._send(200, INFO_PAGE)
            else:
                self._send(403, "Forbidden")
            return

        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
