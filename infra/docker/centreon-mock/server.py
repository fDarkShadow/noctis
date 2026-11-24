#!/usr/bin/env python3
"""Mock Centreon — CVE-2014-3828 / CVE-2014-3829 displayServiceStatus.php SQLi.

Vuln mode: a GET to include/views/graphs/graphStatus/displayServiceStatus.php
(at / or under /centreon) whose raw session_id carries the encoded boolean SQL
payload (`0' or 1=1 -- /**`) "passes" the session lookup and reaches the shell
graphing command, whose error is echoed in the response.
Patched mode: the script validates session_id and answers with an empty
graph page without any shell output.
"""
import os
import ssl
import threading
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CENTREON_MODE", "patched") == "vuln"

SCRIPT = "/include/views/graphs/graphStatus/displayServiceStatus.php"
PAYLOAD_MARKER = "session_id=0%27%20or%201%3D1"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path is the raw request target: %xx sequences are preserved.
        parts = urlsplit(self.path)
        if parts.path in (SCRIPT, "/centreon" + SCRIPT):
            if VULN_MODE and parts.query.startswith(PAYLOAD_MARKER):
                self._send(200, "sh: graph: command not found\n", "text/plain")
            else:
                self._send(200, "", "image/png")
        elif parts.path in ("/", "/centreon", "/centreon/", "/centreon/index.php"):
            self._send(200, "<html><head><title>Centreon - IT &amp; Network Monitoring</title></head>"
                            "<body><form name=\"login\" action=\"index.php\" method=\"post\"></form></body></html>")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
