#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SMARTERMAIL_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/api/v1/auth/force-reset-password":
            if not VULN_MODE:
                self._send(401, b'{"success":false,"message":"Authentication required"}')
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length))
            except Exception:
                self._send(400, b'{"success":false,"message":"Invalid JSON"}')
                return
            is_sysadmin = str(data.get("IsSysAdmin", "")).lower() == "true"
            username = data.get("Username", "")
            new_pass = data.get("NewPassword", "")
            confirm = data.get("ConfirmPassword", "")
            if is_sysadmin and username == "admin" and new_pass and new_pass == confirm:
                self._send(200, b'{"success":true,"debugInfo":"Password updated for user admin","message":null}')
            else:
                self._send(400, b'{"success":false,"message":"Invalid request"}')
        else:
            self._send(404, b'{"success":false,"message":"Not found"}')

    def do_GET(self):
        self._send(404, b'{"success":false,"message":"Not found"}')

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
