#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ELEARNING_SERVER_MODE", "patched") == "vuln"

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
        # News endpoint — the injectable nid parameter.
        if p.startswith("/news.php4"):
            pl = p.lower()
            if VULN_MODE and "union" in pl and "0x53514c2d496e6a656374696f6e2d54657374" in pl:
                # Vulnerable: the UNION SELECT reflects the hex-decoded marker column.
                self._send(200,
                    "<html><body><h1>News</h1>"
                    "<div class='news-title'>%s</div>"
                    "<p>No further news.</p></body></html>" % MARKER)
            else:
                # Patched (or benign request): normal news page, no reflection.
                self._send(200,
                    "<html><body><h1>News</h1>"
                    "<p>No news item found.</p></body></html>")
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
