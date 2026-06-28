#!/usr/bin/env python3
import os, ssl, threading, json
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("FORTIOS_MODE", "patched") == "vuln"
VERSION = "v7.2.5" if VULN_MODE else "v7.2.8"

LOGIN_HTML = f"""<html><head><title>SSL VPN Login</title></head>
<body>
<!-- FortiGate {VERSION[1:]} -->
<form action="/remote/logincheck" method="post">
<p>FortiGate SSL VPN</p>
<input type="text" name="username"/>
<input type="password" name="credential"/>
</form>
</body></html>"""

FIRMWARE_JSON = json.dumps({
    "result": {
        "current": {
            "version": VERSION,
            "build": 1234,
            "branch_point": 1234,
            "release_version_info": "GA"
        }
    },
    "status": "success"
})

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/remote/login":
            self._send(200, LOGIN_HTML)
        elif self.path == "/api/v2/monitor/system/firmware":
            self._send(200, FIRMWARE_JSON, "application/json")
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
