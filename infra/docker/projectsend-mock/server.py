#!/usr/bin/env python3
import os, ssl, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("PROJECTSEND_MODE", "patched") == "vuln"

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
        if self.path == "/options.php":
            # Always redirect unauthenticated GET to login (both vuln and patched)
            self.send_response(302)
            self.send_header("Location", "/login.php")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(200, "<html><body>ProjectSend</body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        if self.path == "/options.php":
            if VULN_MODE:
                # Accept the POST without CSRF validation — return changes_saved indicator
                self._send(200, "<html><body><div id=\"changes_saved\">Settings saved successfully.</div></body></html>")
            else:
                # Patched: reject invalid CSRF token
                self._send(200, "<html><body><div class=\"error\">Invalid or missing CSRF token. Please try again.</div></body></html>")
        else:
            self._send(404, "<html><body>Not found</body></html>")

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
