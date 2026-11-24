#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CLIPBUCKET_MODE", "patched") == "vuln"

# Marker reflected by the injected UNION SELECT concat() column, per the OpenVAS
# plugin. The hex 0x53514c2d496e6a656374696f6e2d54657374 decodes to
# "SQL-Injection-Test"; the mock reflects it ONLY when that literal is sent.
MARKER = "SQL-Injection-Test"
MARKER_HEX = "53514c2d496e6a656374696f6e2d54657374"

# ClipBucket fingerprint — served in both modes (NASL extra_check ">ClipBucket").
BRAND = ">ClipBucket"

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
        # Page view endpoint — the injectable pid parameter.
        if p.startswith("/view_page.php"):
            if VULN_MODE and MARKER_HEX in p.lower():
                # Vulnerable: the concat() column reflects the marker into the page.
                self._send(200,
                    "<html><head><title>ClipBucket</title></head><body>"
                    "<h1%s</h1>"
                    "<div class='page-title'>%s<br/></div>"
                    "<a href='login.php'>Login</a></body></html>" % (BRAND, MARKER))
            else:
                # Patched, or benign/incomplete request: normal ClipBucket page.
                self._send(200,
                    "<html><head><title>ClipBucket</title></head><body>"
                    "<h1%s</h1>"
                    "<p>Page not available.</p>"
                    "<a href='login.php'>Login</a></body></html>" % BRAND)
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
