#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("FORTIWEB_MODE", "patched") == "vuln"

STATUS_BODY = json.dumps({
    "serial": "FV3K0ET123456789",
    "device_type": "FortiWeb",
    "fortiweb": "7.4.5",
    "status": "active",
}, separators=(',', ':')).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path != "/api/fabric/device/status":
            self._send(404, b'{"error":"Not found"}')
            return

        auth = self.headers.get("Authorization", "")
        sql_injected = "'or'1'='1" in auth or "or'1'='1" in auth.lower()

        if VULN_MODE and sql_injected:
            self._send(200, STATUS_BODY)
        else:
            self._send(401, b'{"error":"Authentication required"}')


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
