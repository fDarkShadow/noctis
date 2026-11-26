#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SIMPLEHELP_MODE", "patched") == "vuln"

TRAVERSAL_PATH = "/toolbox-resource/../serverconfig.xml"

CONFIG_XML = (
    "<SimpleSuite><Settings>"
    "<HashPassword>noctis_hash_AAAA1234</HashPassword>"
    "<AdminUser>admin</AdminUser>"
    "</Settings></SimpleSuite>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == TRAVERSAL_PATH:
            if VULN_MODE:
                self._send(200, CONFIG_XML, "application/octet-stream")
            else:
                self._send(403, "Forbidden")
        else:
            self._send(404, "Not Found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
