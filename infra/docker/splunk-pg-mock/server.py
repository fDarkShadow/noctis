#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SPLUNK_MODE", "patched") == "vuln"

DAG_AUTH = "Basic ZGFnOg=="
BACKUP_PATH = "/en-US/splunkd/__raw/v1/postgres/recovery/backup"
DECODE_ERR = b"Failed to decode backup request"
UNAUTH = b"Unauthorized"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != BACKUP_PATH:
            self._send(404, b"Not found")
            return

        self._read_body()
        auth = self.headers.get("Authorization", "")

        if VULN_MODE and auth == DAG_AUTH:
            self._send(400, DECODE_ERR)
        else:
            self._send(401, UNAUTH)

    def do_GET(self):
        self._send(404, b"Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
