#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("QLIK_SENSE_MODE", "patched") == "vuln"

# Raw path prefix that signals a path traversal to the internal QRS API.
# Python's BaseHTTPRequestHandler does NOT normalise .. segments in self.path,
# so the raw traversal string arrives intact from tcp_connect.
QRS_TRAVERSAL = "/../../../qrs/"
QRS_TRAVERSAL_ALT = "/../../qrs/"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Check for path traversal targeting the QRS API
        is_traversal = (QRS_TRAVERSAL in self.path or QRS_TRAVERSAL_ALT in self.path)

        if is_traversal:
            if VULN_MODE:
                # Vulnerable: issue anonymous session cookie + QRS error body
                body = (
                    '{"status":400,"error":"The comparison expression does not '
                    'consist of three elements","path":"/qrs/ReloadTask"}'
                )
                self._send(
                    400,
                    body,
                    ct="application/json",
                    extra_headers={
                        "Set-Cookie": "X-Qlik-Session=aabbccdd-eeee-ffff-0000-111122223333; Path=/; HttpOnly",
                    },
                )
            else:
                # Patched: reject traversal, no session cookie
                self._send(404, "Not Found")
        elif self.path.startswith("/resources/"):
            # Normal static resource request
            self._send(200, "", ct="application/octet-stream")
        else:
            # Qlik Sense login page
            self._send(
                200,
                "<html><head><title>Qlik Sense</title></head>"
                "<body><h1>Qlik Sense</h1></body></html>",
                ct="text/html",
            )

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
