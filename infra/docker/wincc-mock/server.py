#!/usr/bin/env python3
# Mock of a Siemens SIMATIC WinCC HMI "Miniweb" web server.
# vuln:    serves /www/start.html with the "Miniweb Start Page" marker
#          (an exposed, affected Miniweb instance).
# patched: start page removed / not exposed → 404, no marker → zero findings.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WINCC_MODE", "patched") == "vuln"

START_PAGE = (
    "<html><head><title>Miniweb Start Page</title></head>"
    "<body><h1>Miniweb Start Page</h1>"
    "<p>SIMATIC WinCC - Miniweb</p></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    # Advertise a Miniweb-like server banner.
    server_version = "Miniweb"
    sys_version = ""

    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if VULN_MODE and self.path == "/www/start.html":
            self._send(200, START_PAGE)
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
