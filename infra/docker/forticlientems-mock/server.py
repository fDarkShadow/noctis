#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("FORTICLIENTEMS_MODE", "patched") == "vuln"

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

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        if self.path == "/api/v1/auth":
            try:
                data = json.loads(raw)
                username = data.get("username", "")
            except Exception:
                username = ""

            has_sqli = "'" in username

            if VULN_MODE and has_sqli:
                body = json.dumps({
                    "error": "NOCTIS_FORTICLIENTEMS_SQLI",
                    "detail": "Unclosed quotation mark after the character string '''."
                })
                self._send(500, body)
            elif VULN_MODE:
                self._send(401, json.dumps({"error": "Invalid credentials"}))
            elif has_sqli:
                self._send(400, json.dumps({"error": "Bad Request", "detail": "Invalid input"}))
            else:
                self._send(401, json.dumps({"error": "Invalid credentials"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_GET(self):
        if self.path in ("/", "/api/v1/info"):
            version = "7.2.2" if VULN_MODE else "7.2.3"
            self._send(200, json.dumps({"product": "FortiClient EMS", "version": version}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))


if __name__ == "__main__":
    serve(Handler, HTTPServer)
