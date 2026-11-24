#!/usr/bin/env python3
# Mock for Elite Bulletin Board SQL injection — CVE-2012-5874.
# Detection ported from OpenVAS/Greenbone NASL (GPL-2.0-only)
# 2012/gb_elite_bulletin_board_mult_sql_inj_vuln.nasl.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("EBB_MODE", "patched") == "vuln"

LANDING = (
    "<html><head><title>Elite Bulletin Board</title></head>"
    "<body><h1>>Elite Bulletin Board<</h1>"
    "<p>Welcome to Elite Bulletin Board 2.1.21</p></body></html>"
)

# Leaked MySQL backend error produced by the unsanitised SQLi payload.
SQLI_LEAK = (
    "<html><body>"
    "<b>Warning</b>: mysql_fetch_array(): supplied argument is not a valid "
    "MySQL result resource in <b>/includes/db.php</b> on line 128<br>"
    "MySQL server error: You have an error in your SQL syntax near "
    "'name_const(version(),1)' -- SQL Command failed. Grouplist query aborted."
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path keeps the raw, URL-encoded request path (%27/%28/...).
        if self.path == "/index.php" or self.path == "/":
            self._send(200, LANDING)
        elif self.path.startswith("/viewtopic.php"):
            if VULN_MODE:
                # Unsanitised input reaches the SQL query → backend error leaks.
                self._send(200, SQLI_LEAK)
            else:
                # Patched: input sanitised, normal (empty) topic view, no leak.
                self._send(200, "<html><body>No such topic.</body></html>")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
