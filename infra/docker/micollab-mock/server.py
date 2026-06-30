#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("MICOLLAB_MODE", "patched") == "vuln"

AXIS2_SERVICES = (
    "<html><body>"
    "Available services<br/>"
    "Service Description<br/>"
    "NuPointWSService"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/npm-pwg/..;/axis2-AWC/services/listServices":
            if VULN_MODE:
                self._send(200, AXIS2_SERVICES)
            else:
                self._send(403, "Forbidden", "text/plain")
        elif self.path == "/npm-pwg/services/listServices":
            self._send(403, "Forbidden", "text/plain")
        else:
            self._send(404, "Not Found", "text/plain")

    def do_POST(self):
        self._send(404, "Not Found", "text/plain")


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
