#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ESG_MODE", "patched") == "vuln"

# Firmware version embedded in HTML comment
FIRMWARE_VERSION = "9.2.0.001" if VULN_MODE else "9.2.0.006"

LOGIN_PAGE = f"""<!DOCTYPE html>
<html>
<head>
  <title>Barracuda Email Security Gateway</title>
  <!-- firmware-version: {FIRMWARE_VERSION} -->
</head>
<body>
  <div id="login-container">
    <h1>Barracuda Email Security Gateway</h1>
    <p>Please log in to access the management interface.</p>
    <form method="POST" action="/cgi-bin/userlogin.cgi">
      <label>Username: <input type="text" name="user"></label>
      <label>Password: <input type="password" name="password"></label>
      <input type="submit" value="Login">
    </form>
  </div>
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
        if self.path == "/" or self.path == "":
            self._redirect("/cgi-bin/userlogin.cgi")
        elif self.path.startswith("/cgi-bin/userlogin.cgi"):
            self._send(200, LOGIN_PAGE)
        else:
            self._send(404, b"Not found", "text/plain")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
