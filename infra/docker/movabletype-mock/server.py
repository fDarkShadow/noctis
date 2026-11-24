#!/usr/bin/env python3
"""Mock for CVE-2021-20837 — Movable Type (CVSS 9.8)
Ported from OpenVAS NASL 2021/sixapart/gb_movable_type_rce_vuln_oct21_active.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("MOVABLETYPE_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def do_GET(self):
        self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/mt/mt-xmlrpc.cgi":
            data = self._body()
            if VULN_MODE and "mt.handler_to_coderef" in data:
                self._send(200, "<?xml version=\"1.0\"?><methodResponse><params><param><value><string>"
                                "root:x:0:0:root:/root:/bin/bash\n</string></value></param></params></methodResponse>", ct="text/xml")
            else:
                self._send(200, "<?xml version=\"1.0\"?><methodResponse><fault><value><struct>"
                                "<member><name>faultString</name><value><string>Not allowed</string></value></member>"
                                "</struct></value></fault></methodResponse>", ct="text/xml")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
