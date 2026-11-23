#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("REFBASE_MODE", "patched") == "vuln"

# Markers the NASL confirms: the injected SQL-INJECTION-TEST value, the forged
# SQL error string, and the refbase product string.
MARKER = "SQL-INJECTION-TEST"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        # rss.php — the injectable 'where' parameter.
        if p.startswith("/rss.php"):
            if VULN_MODE and "union" in p.lower() and "where=" in p.lower():
                # Vulnerable: the UNION ALL SELECT reflects the injected marker
                # column into the feed, together with the forged SQL error and
                # a redirect whose Location carries the reflected value.
                body = (
                    "<?xml version=\"1.0\"?>\n"
                    "<rss version=\"2.0\"><channel>"
                    "<title>refbase RSS</title>"
                    "<description>version:You have an error in your sql syntax"
                    "%s</description>"
                    "</channel></rss>" % MARKER
                )
                self._send(302, body, ct="text/xml",
                           extra_headers=[("Location", "/show.php?record=%s" % MARKER)])
            else:
                # Patched (or benign request): normal RSS feed, no reflection.
                self._send(200,
                    "<?xml version=\"1.0\"?>\n"
                    "<rss version=\"2.0\"><channel>"
                    "<title>refbase RSS</title>"
                    "<description>Reference database feed</description>"
                    "</channel></rss>", ct="text/xml")
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
