#!/usr/bin/env python3
"""Mock Cotonti CMS — CVE-2013-4789 'c' parameter SQL injection.

/index.php (no injection) always serves the Cotonti front page fingerprint
("Cotonti<" + ">Stay tuned") so the detection's fingerprint step matches in
both modes. The error-based SQLi payload (e=rss & c='and(select...) is
reflected only in vuln mode as a MySQL duplicate-entry error that leaks the
DB version; patched mode returns a clean RSS page with no error.

The feed sends the payload via a raw HTTP/1.0 request, so the handler inspects
the raw request path (self.path keeps %xx encoding intact). The NASL also
probes an optional /cotonti install dir, so a leading /cotonti is accepted.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("COTONTI_MODE", "patched") == "vuln"

FINGERPRINT = (
    "<!DOCTYPE html><html><head><title>Cotonti</title>"
    "<meta name=\"generator\" content=\"Cotonti</span> Siena\"></head>"
    "<body><h1><span>Cotonti</span></h1><p>Stay tuned, more content is coming soon.</p>"
    "</body></html>"
)

# MySQL error-based SQLi leak; matches "SQL error 23000: .*Duplicate entry.*group_key"
SQL_ERROR = (
    "<b>Fatal error</b>: Uncaught exception in system/database.php: "
    "SQL error 23000: Duplicate entry '5.5.42-MariaDB1' for key 'group_key' "
    "in /var/www/cotonti/system/database.php on line 420\n"
)


class Handler(BaseHTTPRequestHandler):
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
        raw = self.path
        # Accept an optional /cotonti install-dir prefix (NASL iterates it).
        if raw.startswith("/cotonti/"):
            raw = raw[len("/cotonti"):]

        if raw.startswith("/index.php"):
            # Error-based SQLi: e=rss with the injected 'c' payload.
            if "e=rss" in raw and "c='and(select" in raw:
                if VULN_MODE:
                    self._send(200, SQL_ERROR)
                else:
                    # Patched: input sanitised — normal (empty) RSS feed, no error.
                    self._send(200, "<?xml version=\"1.0\"?><rss version=\"2.0\"><channel>"
                                    "<title>Cotonti</title></channel></rss>",
                               ct="application/rss+xml")
                return
            # Plain front page: fingerprint (served in both modes).
            self._send(200, FINGERPRINT)
            return

        self._send(404, "Not Found")

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
