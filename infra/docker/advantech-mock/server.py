#!/usr/bin/env python3
"""Mock Advantech Studio NTWebServer — CVE-2013-1627 directory traversal.

Both modes serve /startup.html with the ``Advantech`` product marker the feed's
preliminary gate looks for. The difference is the traversal:

  vuln   : a ``../`` sequence request for a Windows system file (boot.ini /
           win.ini) returns HTTP 200 with the leaked file content.
  patched : the same traversal request is rejected (404) and no file content is
           leaked, while /startup.html still identifies as Advantech — a real
           TN (the product is present, only the traversal is fixed).

The raw request path is matched against ``self.path`` so the verbatim ``../``
sequence sent by the feed's tcp_connect step is preserved (not normalised).
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ADVANTECH_MODE", "patched") == "vuln"

# Advantech Studio NTWebServer landing page — carries the "Advantech" marker
# the feed's gate (GET /startup.html) requires. Served in both modes.
STARTUP_PAGE = (
    "<html><head><title>Advantech Studio Web Thin Client</title></head>"
    "<body>Advantech Studio NTWebServer</body></html>"
)

# Leaked Windows system files (vuln mode only).
BOOT_INI = (
    "[boot loader]\r\n"
    "timeout=30\r\n"
    "default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\r\n"
    "[operating systems]\r\n"
    "multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS=\"Windows\"\r\n"
)
WIN_INI = (
    "; for 16-bit app support\r\n"
    "[fonts]\r\n"
    "[extensions]\r\n"
    "[mci extensions]\r\n"
    "[files]\r\n"
    "[Mail]\r\nMAPI=1\r\n"
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
        # self.path preserves the raw "../" sequence of the tcp_connect request.
        path = self.path
        if path == "/startup.html":
            self._send(200, STARTUP_PAGE)
            return
        # Directory traversal attempt.
        if "../" in path:
            if VULN_MODE and path.endswith("boot.ini"):
                self._send(200, BOOT_INI, ct="text/plain")
                return
            if VULN_MODE and path.endswith("win.ini"):
                self._send(200, WIN_INI, ct="text/plain")
                return
            # Patched (sanitised) or unknown traversal target.
            self._send(404, "Not Found")
            return
        self._send(404, "Not Found")

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
