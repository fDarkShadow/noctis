#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("LANGFLOW_MODE", "patched") == "vuln"

PASSWD_DETAIL = (
    '{"detail": "b\'root:x:0:0:root:/root:/bin/bash\\n'
    'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\\n\'"}'
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self._read_body()
        if self.path == "/api/v1/validate/code":
            if VULN_MODE and b"subprocess" in body:
                self._send(200, PASSWD_DETAIL)
            else:
                self._send(401, '{"detail": "Unauthorized"}')
        else:
            self._send(404, '{"detail": "Not Found"}')

    def do_GET(self):
        self._send(404, '{"detail": "Not Found"}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
