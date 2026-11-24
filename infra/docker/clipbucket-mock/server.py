#!/usr/bin/env python3
"""ClipBucket 2.6 mock — videos.php `time` parameter SQL injection
(CVE-2012-6642 / CVE-2012-6643 / CVE-2012-6644).

vuln:    a quote in `time` breaks the SQL query → 200 + MySQL syntax error
         echoing the injected value.
patched: the parameter is sanitised → normal video listing, no SQL error.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

VULN_MODE = os.environ.get("CLIPBUCKET_MODE", "patched") == "vuln"

LISTING = (
    "<html><head><title>Videos - ClipBucket</title></head><body>"
    "<h1>Videos</h1><div class='videos'>No videos found</div>"
    "<p>ClipBucket Copyright &copy; 2007 - 2012</p></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path in ("/videos.php", "/clipbucket/videos.php"):
            time_v = parse_qs(parts.query, keep_blank_values=True).get("time", [""])[0]
            if VULN_MODE and "'" in time_v:
                body = (
                    "<html><body><b>Database error:</b> You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server version for the "
                    "right syntax to use near '" + time_v.split("'", 1)[1] +
                    "' ORDER BY date_added DESC LIMIT 0,20' at line 1</body></html>"
                )
                self._send(200, body)
            else:
                self._send(200, LISTING)
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self): self.do_GET()


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
