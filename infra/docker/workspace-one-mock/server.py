#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from mocklib import serve

VULN_MODE = os.environ.get("WORKSPACE_ONE_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/catalog-portal/ui/oauth/verify":
            params = parse_qs(parsed.query, keep_blank_values=True)
            device_udid = unquote(params.get("deviceUdid", [""])[0])
            if VULN_MODE:
                if any(kw in device_udid for kw in ["freemarker", "Execute", "${"]):
                    self._send(400, '{"error":"Authorization context is not valid","code":400}')
                else:
                    self._send(400, '{"error":"Missing required parameter","code":400}')
            else:
                self._send(400, '{"error":"Invalid deviceUdid parameter","code":400}')
        else:
            self._send(200, '{"name":"VMware Workspace ONE"}', "text/html")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
