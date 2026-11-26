#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SCREENCONNECT_MODE", "patched") == "vuln"

WIZARD_PAGE = b"""<!DOCTYPE html>
<html><head><title>ScreenConnect Setup Wizard</title></head><body>
<form method="POST" action="/SetupWizard.aspx">
  <input type="text" name="AdminEmail" placeholder="Admin Email" />
  <input type="text" name="ServerAddress" placeholder="Server Address" />
  <input type="submit" name="FinishButton" value="Finish" />
</form>
</body></html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/SetupWizard.aspx":
            if VULN_MODE:
                self._send(200, WIZARD_PAGE)
            else:
                self._send(302, b"", extra_headers={"Location": "/Administration"})
        elif self.path == "/Administration":
            self._send(200, b"<html><body>Administration</body></html>")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
