#!/usr/bin/env python3
"""WordPress WP Symposium mock — CVE-2015-6522 (get_album_item.php SQLi).

vuln:    get_album_item.php evaluates the `size` parameter as SQL; the
         `version() ; --` payload returns the MySQL version string with a
         PHPSESSID session cookie.
patched: WP Symposium 15.8+ — the injected `size` is rejected (empty 200 body,
         no session cookie, no query result).
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

VULN_MODE = os.environ.get("WPSYMPOSIUM_MODE", "patched") == "vuln"
ENDPOINT = "/wp-content/plugins/wp-symposium/get_album_item.php"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html; charset=UTF-8", cookie=False):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("X-Powered-By", "PHP/5.5.9-1ubuntu4.11")
        if cookie:
            self.send_header("Set-Cookie", "PHPSESSID=4k1v0mq3t9a6r2b8c5d7e1f0g3; path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path.startswith("/wordpress/"):
            path = path[len("/wordpress"):]
        if path == ENDPOINT:
            size = parse_qs(parts.query).get("size", [""])[0]
            if VULN_MODE and "version()" in size.lower():
                self._send(200, "5.5.44-0ubuntu0.14.04.1", cookie=True)
            else:
                self._send(200, "")
        elif path in ("/", ""):
            self._send(200, "<html><head><meta name=\"generator\" content=\"WordPress 4.2.4\" /></head><body>Blog</body></html>")
        else:
            self._send(404, "Not found", ct="text/plain")

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
