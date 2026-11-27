#!/usr/bin/env python3
"""WordPress WP Symposium mock — CVE-2015-6522 (get_album_item.php SQLi).

vuln:    get_album_item.php evaluates the `size` parameter as SQL; the
         `version() ; --` payload returns the MySQL version string with a
         PHPSESSID session cookie.
patched: WP Symposium 15.8+ — get_album_item.php still calls session_start()
         (so a PHPSESSID cookie is set regardless of version) and returns a
         normal album-item response that contains digits (dimensions, IDs),
         but the injected `size` is sanitised, so the body is NOT a version()
         query result. The stricter feed pattern must come out clean here.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from mocklib import serve

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
                # SQLi executes: the version() result is returned as the body.
                self._send(200, "5.5.44-0ubuntu0.14.04.1", cookie=True)
            else:
                # Patched 15.8+: session_start() still sets PHPSESSID, and the
                # endpoint answers with a normal album-item body that contains
                # digits but is NOT a MySQL version string.
                self._send(
                    200,
                    "<img src=\"album/thumb.jpg\" width=\"150\" height=\"150\" alt=\"item 4821\">",
                    cookie=True,
                )
        elif path in ("/", ""):
            self._send(200, "<html><head><meta name=\"generator\" content=\"WordPress 4.2.4\" /></head><body>Blog</body></html>")
        else:
            self._send(404, "Not found", ct="text/plain")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
