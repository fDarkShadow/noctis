#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("CACTI_MODE", "patched") == "vuln"

POLL_RESPONSE = json.dumps([{"value": "1", "local_data_id": 1}])

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
        parsed = urlparse(self.path)
        xff = self.headers.get("X-Forwarded-For", "")

        if parsed.path == "/remote_agent.php":
            if VULN_MODE and "127.0.0.1" in xff:
                self._send(200, POLL_RESPONSE)
            else:
                self._send(403, json.dumps({"error": "Forbidden"}))
        else:
            self._send(200, b"<html><head><title>Login to Cacti</title></head><body>Login</body></html>",
                       ct="text/html")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
