#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PANOS_GP_MODE", "patched") == "vuln"

GP_LOGIN_HTML = b"""<!DOCTYPE html>
<html>
<head><title>GlobalProtect</title></head>
<body>
  <div class="pan_form_">
    <h1>GlobalProtect VPN Portal</h1>
    <form method="post" action="/global-protect/login.esp">
      <input type="text" name="user" placeholder="Username">
      <input type="password" name="passwd" placeholder="Password">
      <input type="submit" value="Sign In">
    </form>
  </div>
</body>
</html>
"""

PRELOGIN_SUCCESS = b"""<?xml version="1.0" encoding="UTF-8"?>
<prelogin-cookie>
  <status>Success</status>
  <msg>Connected</msg>
  <cookie>NOCTIS_GP_COOKIE</cookie>
</prelogin-cookie>
"""

PRELOGIN_ERROR = b"""<?xml version="1.0" encoding="UTF-8"?>
<prelogin-cookie>
  <status>Error</status>
  <msg>Authentication required</msg>
</prelogin-cookie>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", location=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        if self.path.startswith("/global-protect/login.esp"):
            self._send(200, GP_LOGIN_HTML)
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        self._read_body()
        if self.path.startswith("/ssl-vpn/prelogin.esp"):
            if VULN_MODE:
                self._send(200, PRELOGIN_SUCCESS, "application/xml")
            else:
                self._send(401, PRELOGIN_ERROR, "application/xml")
        else:
            self._send(404, b"Not found")


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
