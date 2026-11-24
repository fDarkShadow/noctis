#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CSA_MODE", "patched") == "vuln"

# When tcp_connect sends the raw request, Python's BaseHTTPRequestHandler
# sets self.path to the raw un-decoded URL. The traversal payload arrives
# as /client/index.php%3F.php/gsb/users.php with %3F intact.
TRAVERSAL_MARKER = "%3F"
TRAVERSAL_MARKER_LC = "%3f"

ADMIN_PANEL_HTML = (
    "<html><head><title>Ivanti Cloud Services Appliance</title></head>"
    "<body>"
    "<h1>Ivanti Cloud Services Appliance</h1>"
    "<h2>User Management</h2>"
    "<form method='post'>"
    "<label>User name</label><input type='text' name='username'/><br/>"
    "<label>Set Password</label><input type='password' name='password'/><br/>"
    "<input type='submit' value='Save'/>"
    "</form>"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        raw = self.path
        is_traversal = (TRAVERSAL_MARKER in raw or TRAVERSAL_MARKER_LC in raw)

        if is_traversal:
            if VULN_MODE:
                self._send(200, ADMIN_PANEL_HTML)
            else:
                self._send(403, "<html>Access Denied</html>")
        elif raw == "/" or raw.startswith("/client"):
            self._send(
                200,
                "<html><head><title>LandDesk(R) Cloud Services Appliance</title></head>"
                "<body><h1>Ivanti CSA</h1></body></html>",
            )
        else:
            self._send(404, "<html>Not Found</html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
