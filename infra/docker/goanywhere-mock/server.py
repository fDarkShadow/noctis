#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("GOANYWHERE_MODE", "patched") == "vuln"

_SETUP_WIZARD_HTML = """\
<!DOCTYPE html>
<html>
<head><title>GoAnywhere MFT - Initial Setup</title></head>
<body>
<h1>Create an administrator account</h1>
<p>Welcome to GoAnywhere MFT. Please create an administrator account to get started.</p>
<form method="POST" action="/goanywhere/wizard/InitialAccountSetup.xhtml">
  <label>Username: <input name="username" type="text"/></label><br/>
  <label>Password: <input name="password" type="password"/></label><br/>
  <input type="submit" value="Create Account"/>
</form>
<p>Powered by goanywhere MFT</p>
</body>
</html>"""


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
        # Match the ..;/ bypass path and the direct wizard path
        if "InitialAccountSetup.xhtml" in self.path:
            if VULN_MODE:
                self._send(200, _SETUP_WIZARD_HTML)
            else:
                self._send(403, b"<html><body>403 Forbidden</body></html>")
        else:
            self._send(404, b"<html><body>404 Not Found</body></html>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)
        self._send(403, b"<html><body>403 Forbidden</body></html>")


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
