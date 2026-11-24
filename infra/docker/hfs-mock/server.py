#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from mocklib import serve

VULN_MODE = os.environ.get("HFS_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        decoded_path = unquote(self.path)
        is_injection = "cmd=" in decoded_path and (
            "exec" in decoded_path or "{." in decoded_path
        )

        if VULN_MODE and is_injection:
            parsed = urlparse(decoded_path)
            params = parse_qs(parsed.query)
            cmd = params.get("cmd", [""])[0]
            body = f"<html><body>RESULT:\n{cmd}\n====</body></html>"
            self._send(200, body)
        else:
            self._send(200, "<html><title>HFS - HTTP File Server</title></html>")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
