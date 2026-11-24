#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("WHD_MODE", "patched") == "vuln"

# Version embedded in asset URLs: vuln=12.8.2.1, patched=12.8.3.1
VERSION = "12_8_2_1" if VULN_MODE else "12_8_3_1"

WHD_PAGE = f"""<!DOCTYPE html>
<html>
<head>
  <title>SolarWinds Web Help Desk</title>
  <link rel="stylesheet" href="/resources/css/main.css?v={VERSION}">
  <script src="/resources/js/app.js?v={VERSION}"></script>
</head>
<body>
  <div id="header">
    <span class="product-name">Web Help Desk Software</span>
    <span class="vendor">SolarWinds WorldWide, LLC</span>
  </div>
  <form id="loginForm" action="/helpdesk/WebObjects/Helpdesk.woa/wa/LoginActions/login" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Log In">
  </form>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/helpdesk") and "Helpdesk.woa" not in self.path:
            self._redirect("/helpdesk/WebObjects/Helpdesk.woa")
        elif "Helpdesk.woa" in self.path:
            self._send(200, WHD_PAGE)
        else:
            self._send(404, b"Not found", "text/plain")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
