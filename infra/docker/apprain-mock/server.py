#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("APPRAIN_MODE", "patched") == "vuln"

# Bounded marker matched by ov-sql-inj-test:[0-9]+.*:ov-sql-inj-test
MARKER = "ov-sql-inj-test:424242:appRain:ov-sql-inj-test"

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
        p = self.path
        # Profile endpoint — the injectable SQLi sink.
        if p.startswith("/profile/index.php"):
            if VULN_MODE:
                # Vulnerable: the injected UNION SELECT reflects the bounded marker.
                self._send(200,
                    "<html><body><h1>Profile</h1>"
                    "<div class='profile-field'>%s</div>"
                    "</body></html>" % MARKER)
            else:
                # Patched: normal profile page, no reflection.
                self._send(200,
                    "<html><body><h1>Profile</h1>"
                    "<p>No profile found.</p></body></html>")
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

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
