#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("GRAVITYBOARDX_MODE", "patched") == "vuln"

# Hex 0x53514c2d496e6a656374696f6e2d54657374 decodes to this marker.
MARKER = "SQL-Injection-Test"

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
        # viewboard action — the injectable board_id parameter.
        if p.startswith("/index.php") and "action=viewboard" in p:
            if VULN_MODE and "union" in p.lower() and "gbx_members" in p.lower():
                # Vulnerable: the UNION SELECT reflects the marker column into output.
                self._send(200,
                    "<html><body><h1>Gravity Board X</h1>"
                    "<div class='board'><span>%s</span></div>"
                    "</body></html>" % MARKER)
            else:
                # Patched (or benign request): normal board page, no reflection.
                self._send(200,
                    "<html><body><h1>Gravity Board X</h1>"
                    "<p>No such board.</p></body></html>")
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
