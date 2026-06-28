#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("TELERIK_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def do_POST(self):
        self._read_body()  # consume body to keep connection clean

        if self.path == "/Startup/Register":
            if VULN_MODE:
                self._send(200, '{"success":true}')
            else:
                self._send(403, '{"error":"Registration is not available"}')

        elif self.path == "/Token":
            if VULN_MODE:
                self._send(
                    200,
                    '{"access_token":"NOCTIS_TOKEN_CONFIRMED",'
                    '"token_type":"bearer","expires_in":86400,'
                    '"userName":"noctis_probe"}',
                )
            else:
                self._send(401, '{"error":"invalid_grant"}')

        else:
            self._send(404, '{"error":"Not Found"}')

    def do_GET(self):
        self._send(
            200,
            "<html><head><title>Log in | Telerik Report Server</title></head>"
            "<body><h1>Telerik Report Server</h1></body></html>",
            ct="text/html",
        )


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
