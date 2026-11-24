#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ZEROCMS_MODE", "patched") == "vuln"

# Hex 0x53514c2d496e6a656374696f6e2d54657374 decodes to this marker; the mock
# reflects it ONLY when that literal is present in the request (not self-fulfilling).
MARKER = "SQL-Injection-Test"
MARKER_HEX = "53514c2d496e6a656374696f6e2d54657374"

# ZeroCMS fingerprint — served in both modes (NASL extra_check >ZeroCMS< / >Login<).
FINGERPRINT = ('<title>ZeroCMS</title>'
               '<div id="nav"><a href="/zero_user_login.php">Login</a></div>')

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
        # zero_view_article.php — the injectable article_id parameter.
        if p.startswith("/zero_view_article.php"):
            if VULN_MODE and MARKER_HEX in p.lower():
                # Vulnerable: the UNION SELECT concat() column reflects the marker.
                self._send(200,
                    "<html><body>%s"
                    "<h1>%s</h1>"
                    "<div class=\"article\">by admin</div>"
                    "</body></html>" % (FINGERPRINT, MARKER))
            else:
                # Patched, or benign/incomplete request: normal ZeroCMS page.
                self._send(200,
                    "<html><body>%s"
                    "<h1>Welcome</h1>"
                    "<div class=\"article\">Article not found.</div>"
                    "</body></html>" % FINGERPRINT)
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
