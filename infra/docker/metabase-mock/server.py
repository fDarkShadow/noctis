#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("METABASE_MODE", "patched") == "vuln"

PASSWD_CONTENT = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/geojson":
            params = parse_qs(parsed.query)
            url = params.get("url", [""])[0]
            if VULN_MODE and url.startswith("file://"):
                self._send(200, PASSWD_CONTENT)
            else:
                self._send(400, b'{"errors":{"url":"Only http/https URLs are supported."}}', "application/json")
        else:
            self._send(404, b"Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
