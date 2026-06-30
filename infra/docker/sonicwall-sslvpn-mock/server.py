#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SONICWALL_MODE", "patched") == "vuln"

VULN_BODY = (
    "NELaunchX1\n"
    "vpnclient_proto=2\n"
    "pppd_pid=1234\n"
    "client_ip=10.0.0.1\n"
)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/cgi-bin/sslvpnclient"):
            if VULN_MODE:
                self._send(200, VULN_BODY, extra_headers={
                    "Set-Cookie": "swap=NOCTIS_SESSION_TOKEN_1234567890; Path=/; HttpOnly"
                })
            else:
                self._send(401, "Unauthorized")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()

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
