#!/usr/bin/env python3
# Mock for CVE-2010-2861 — Adobe ColdFusion enter.cfm locale directory traversal.
#
# vuln   : the traversal path (locale=../..%00 → lib/password.properties) returns
#          the ColdFusion password config file; every other path (including the
#          benign control request to /CFIDE/administrator/enter.cfm) returns the
#          ordinary admin login page.
# patched: the traversal is rejected — every path returns the login page.
#
# A detection feed must defeat a blanket responder, so the file signature
# (rdspassword= / encrypted=) is served ONLY on the genuine traversal path.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("COLDFUSION_MODE", "patched") == "vuln"

# Benign fixed signature of ColdFusion's lib/password.properties — no real secret.
PASSWORD_PROPERTIES = (
    "#Fri Jul 30 00:00:00 UTC 2010\n"
    "rdspassword=AAFD80C2D0B8B9B2C3D4E5F60718293A\n"
    "password=1A2B3C4D5E6F70819200000000000000\n"
    "encrypted=true\n"
)

LOGIN_PAGE = (
    "<html><head><title>Adobe ColdFusion Administrator Login</title></head>"
    "<body><h1>ColdFusion Administrator</h1>"
    "<form action='enter.cfm' method='post'>"
    "<input type='password' name='cfadminPassword'>"
    "</form></body></html>"
)


def _is_traversal(path):
    # The raw request path must still carry the traversal + NUL marker.
    return (
        "password.properties" in path
        and ".." in path
        and "%00" in path
        and "locale=" in path
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
        if VULN_MODE and _is_traversal(self.path):
            self._send(200, PASSWORD_PROPERTIES, ct="text/plain")
        else:
            self._send(200, LOGIN_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
