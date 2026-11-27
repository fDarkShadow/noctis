#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CSLU_MODE", "patched") == "vuln"

HARDCODED_AUTH = "Basic Y3NsdS13aW5kb3dzLWNsaWVudDpMaWJyYXJ5NEMkTFU="
JOBS_JSON = b'[{"job_name":"license_sync","current_status":"completed","next_run":"2025-04-01T00:00:00Z"},{"job_name":"cleanup","current_status":"pending","next_run":"2025-04-01T01:00:00Z"}]'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/cslu/v1/scheduler/jobs":
            auth = self.headers.get("Authorization", "")
            if VULN_MODE and auth == HARDCODED_AUTH:
                self._send(200, JOBS_JSON)
            else:
                self._send(401, b'{"error":"Unauthorized"}')
        else:
            self._send(404, b'{"error":"Not found"}')

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
