#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("TEAMCITY27199_MODE", "patched") == "vuln"

ADMIN_PAGE = b"""<!DOCTYPE html>
<html>
<head><title>TeamCity -- Diagnostic</title></head>
<body>
<h1>Server Diagnostic</h1>
<section>
  <h2>Debug Logging</h2>
  <p>Configure server debug logging categories and levels.</p>
</section>
<section>
  <h2>CPU &amp; Memory Usage</h2>
  <p>View real-time CPU and memory diagnostics for the TeamCity server.</p>
</section>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, (str, bytes)):
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
        path = self.path

        # Detect path traversal patterns targeting /admin/diagnostic.jsp
        is_traversal = (
            ("%2e" in path.lower() or "/../" in path) and
            "diagnostic.jsp" in path.lower()
        )

        if is_traversal:
            if VULN_MODE:
                # Vulnerable: serve admin diagnostic page without auth
                self._send(200, ADMIN_PAGE)
            else:
                # Patched: redirect all traversal attempts to login
                self._redirect("/login.jsp")
        elif path.lower().endswith("diagnostic.jsp"):
            # Direct access (no traversal) always requires auth
            self._redirect("/login.jsp")
        else:
            self._send(200, b"<html><title>TeamCity</title></html>")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
