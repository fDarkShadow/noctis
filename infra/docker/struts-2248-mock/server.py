#!/usr/bin/env python3
"""Mock Apache Struts — S2-016/S2-017 (CVE-2013-2248, CVE-2013-2251).

DefaultActionMapper prefix injection. A GET to the showcase action carrying a
URL-encoded `redirect:%{N*5}` OGNL expression in the query string makes a
vulnerable instance evaluate the arithmetic and emit a 302 whose Location
reflects the computed value (e.g. 2*5 -> /struts2-showcase/10).

Vuln mode: evaluate the embedded `%{N*M}` product and 302 to it.
Patched mode: the prefix is not evaluated (plain 404 for the crafted request).

The raw query carries %3A %25 %7B %7D, so the detection is sent over a verbatim
tcp_connect request — self.path preserves the escapes, which we decode here.
"""
import os
import re
import ssl
import threading
from urllib.parse import unquote, urlsplit
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("STRUTS_MODE", "patched") == "vuln"

# redirect:%{<int>*<int>}  (after URL-decoding the query)
OGNL_RE = re.compile(r"redirect:%\{\s*(\d+)\s*\*\s*(\d+)\s*\}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path != "/struts2-showcase/showcase.action":
            self._send(404, "Not Found")
            return

        # Decode the raw query (%3A %25 %7B %7D -> :%{ }) and look for the
        # redirect: prefix carrying an OGNL arithmetic expression.
        query = unquote(parts.query)
        m = OGNL_RE.search(query)

        if VULN_MODE and m:
            # Vulnerable Struts evaluates the OGNL expression and redirects to
            # the computed value.
            product = int(m.group(1)) * int(m.group(2))
            self._send(
                302,
                "",
                extra={"Location": "/struts2-showcase/%d" % product},
            )
            return

        # Patched (or no payload): the prefix is not evaluated — plain showcase
        # page, no OGNL-driven redirect.
        self._send(200, "<html><title>Struts2 Showcase</title><body>Welcome!</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
