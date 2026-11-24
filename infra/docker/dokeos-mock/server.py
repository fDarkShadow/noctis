#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("DOKEOS_MODE", "patched") == "vuln"

# Marker reflected by the injected UNION SELECT hex-literal column, per the
# OpenVAS plugin. The hex 0x73716c2d696e6a656374696f6e2d74657374 decodes to
# "sql-injection-test"; the mock only reflects it when that literal is sent.
MARKER = "sql-injection-test"
MARKER_HEX = "73716c2d696e6a656374696f6e2d74657374"

# Dokeos page footer — served in both modes; the feed's secondary check.
FOOTER = "<p>Powered by www.dokeos.com</p>"

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
        # Dokeos index.php — the injectable `language` parameter.
        if p.startswith("/index.php") and "language=" in p:
            # Reflect the marker ONLY when the request actually carries the
            # hex-literal marker column of the UNION SELECT (not self-fulfilling).
            if VULN_MODE and MARKER_HEX in p.lower():
                self._send(200,
                    "<html><head><title>Dokeos</title></head><body>"
                    "<p>%s</p>%s</body></html>" % (MARKER, FOOTER))
            else:
                # Patched, or benign/incomplete request: normal Dokeos page.
                self._send(200,
                    "<html><head><title>Dokeos</title></head><body>"
                    "<p>Welcome to Dokeos</p>%s</body></html>" % FOOTER)
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
