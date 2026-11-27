#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CHECKPOINT_MODE", "patched") == "vuln"

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        if self.path == "/clients/MyCRL":
            if VULN_MODE and "aCSHELL" in body:
                self._send(200, FAKE_PASSWD, ct="text/plain")
            else:
                self._send(403, "Forbidden")
        else:
            self._send(404, "Not Found")

    def do_GET(self):
        self._send(
            200,
            "<html><head><title>Check Point SSL Network Extender</title></head>"
            "<body><h1>Check Point SSL Network Extender</h1></body></html>",
            ct="text/html",
        )


if __name__ == "__main__":
    serve(Handler, HTTPServer)
