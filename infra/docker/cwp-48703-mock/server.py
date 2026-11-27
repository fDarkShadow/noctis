#!/usr/bin/env python3
import os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CWP_MODE", "patched") == "vuln"

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
        if self.path == "/login/index.php":
            self._send(200, "<html>Control WebPanel cwp - Login</html>")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if "/index.php" in self.path and "filemanager" in self.path and "changePerm" in self.path:
            if not VULN_MODE:
                self._send(403, "Permission denied")
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            m = re.search(r"curl\s+(https?://\S+)", body)
            if m:
                url = m.group(1).rstrip("\r\n -")
                try:
                    urllib.request.urlopen(url, timeout=5)
                except Exception:
                    pass
            self._send(200, "OK")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
