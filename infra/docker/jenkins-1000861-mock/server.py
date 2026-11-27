#!/usr/bin/env python3
"""Mock Jenkins — CVE-2018-1000861 Stapler ACL bypass.

Vuln mode:
  GET /search/index                          -> 403 (ACL protects it)
  GET /securityRealm/user/<name>/search/index -> 200, the search runs anyway
Patched mode:
  the securityRealm-prefixed path is ACL-protected too -> 403
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("JENKINS_MODE", "patched") == "vuln"

FORBIDDEN_BODY = (
    "<html><head><title>Error 403 Forbidden</title></head>"
    "<body><h1>HTTP ERROR 403</h1><p>Authentication required.</p>"
    "<hr/><i>Jenkins</i></body></html>"
)

SEARCH_RESULT_BODY = (
    "<html><head><title>Search for 'a' [Jenkins]</title></head>"
    "<body><div id='search-results'>Nothing seems to match.</div>"
    "<i>Jenkins ver. 2.121.1</i></body></html>"
)

ROOT_BODY = (
    "<html><head><title>Dashboard [Jenkins]</title></head>"
    "<body><i>Jenkins ver. 2.121.1</i></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html;charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Hudson", "1.395")
        self.send_header("X-Jenkins", "2.121.1")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        # The ACL-protected search route reached via the securityRealm prefix.
        if (
            path.startswith("/securityRealm/user/")
            and path.endswith("/search/index")
        ):
            if VULN_MODE:
                # Stapler routing reaches the search despite the ACL.
                self._send(200, SEARCH_RESULT_BODY)
            else:
                # Patched: the prefixed path is ACL-protected too.
                self._send(403, FORBIDDEN_BODY)
            return

        # The unprefixed search index is always ACL-protected (both modes).
        if path == "/search/index":
            self._send(403, FORBIDDEN_BODY)
            return

        if path == "/":
            self._send(200, ROOT_BODY)
            return

        self._send(404, "<html><body>Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
