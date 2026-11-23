#!/usr/bin/env python3
"""Mock ASUSTOR ADM — CVE-2018-11509/11510/11511 unauthenticated RCE.

Vuln mode: a GET to /portal/apis/aggrecate_js.cgi whose `script` parameter
carries a `"&<cmd>&"` shell break-out "executes" the injected command (here
`ls -l`) and reflects its directory-listing output (drwx... root root).
Patched mode: the handler rejects the injection (404) → no finding.

The injection payload is URL-encoded (%22/%26/%20) and arrives via raw
tcp_connect, so the handler inspects self.path verbatim (it is NOT decoded).
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ASUSTOR_MODE", "patched") == "vuln"

# Realistic `ls -l` output reflected by the vulnerable CGI.
LS_OUTPUT = (
    "total 20\n"
    "drwxr-xr-x 2 root root 4096 Jun 29  2018 apis\n"
    "drwxr-xr-x 5 root root 4096 Jun 29  2018 portal\n"
    "-rw-r--r-- 1 root root  512 Jun 29  2018 launcher.js\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path keeps the raw, URL-encoded request target (%22/%26/%20).
        if self.path.startswith("/portal/apis/aggrecate_js.cgi"):
            # The injected shell break-out is `%22%26...%26%22` → `"&...&"`.
            if VULN_MODE and "%22%26" in self.path and "%26%22" in self.path:
                self._send(200, "var launcher=\n" + LS_OUTPUT)
            else:
                # Patched: injection stripped/rejected — benign JS, no listing.
                self._send(200, "var launcher={};\n")
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
