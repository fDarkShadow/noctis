#!/usr/bin/env python3
import os, ssl, threading, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("EPMM_MODE", "patched") == "vuln"

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
        if self.path == "/mifs/asfV3/api/v2/admins/users":
            if VULN_MODE:
                data = json.dumps({
                    "results": [{"userId": "admin001", "name": "System Admin", "email": "admin@company.local"}],
                    "totalCount": 1
                })
                self._send(200, data)
            else:
                self._send(401, json.dumps({"error": "Unauthorized", "message": "Authentication required"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
