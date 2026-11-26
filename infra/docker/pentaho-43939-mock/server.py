#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PENTAHO_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/pentaho/Login":
            self._send(200, "<html><title>Pentaho User Console - Login</title></html>")
        elif path == "/pentaho/api/ldap/config/ldapTreeNodeChildren/require.js":
            if VULN_MODE:
                self._send(200, "{}",
                           ct="application/json",
                           extra_headers={"Set-Cookie": "APPSESSIONID=NOCTIS123; Path=/pentaho"})
            else:
                self._send(403, "Forbidden", ct="text/plain")
        else:
            self._send(404, "Not found", ct="text/plain")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
