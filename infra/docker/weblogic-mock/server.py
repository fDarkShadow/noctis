#!/usr/bin/env python3
"""Oracle WebLogic Server mock for CVE-2024-21182 (noctis).

Like a real WebLogic listen port, one socket speaks both HTTP and T3: a
connection whose first line starts with "t3 " gets a T3 HELO, anything else is
handled as HTTP.

WEBLOGIC_MODE:
  vuln          T3 HELO and admin console both report WEBLOGIC_VERSION
                (default 12.2.1.4.0, an affected release; set it to an
                unaffected release such as 12.2.1.3.0 for a negative test).
  vuln_console  T3 refused (connection closed, as a WebLogic connection filter
                does); the admin console still reports WEBLOGIC_VERSION.
  patched       WebLogic 14.1.2.0.0, an unaffected release: T3 HELO reports
                14.1.2.0.0 and there is no admin console (removed in 14.1.2).
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("WEBLOGIC_MODE", "patched")
if MODE not in ("vuln", "vuln_console", "patched"):
    raise SystemExit("unknown WEBLOGIC_MODE: %r" % MODE)
if MODE == "patched":
    VERSION = "14.1.2.0.0"
else:
    VERSION = os.environ.get("WEBLOGIC_VERSION", "12.2.1.4.0")

LOGIN_PAGE = (
    "<!DOCTYPE html>\n<html><head>"
    "<title>Oracle WebLogic Server Administration Console 12c</title>"
    "</head><body>\n"
    '<div id="login-header">WebLogic Server Administration Console</div>\n'
    '<form id="loginData" method="post" action="/console/j_security_check">'
    '<input type="text" name="j_username"/><input type="password" name="j_password"/>'
    "</form>\n"
    '<div id="footer"><p id="footerVersion">WebLogic Server Version: ' + VERSION + "</p>"
    "<p>Copyright &copy; 1996, Oracle and/or its affiliates. All rights reserved.</p></div>\n"
    "</body></html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def parse_request(self):
        # T3 shares the HTTP port: answer the handshake instead of parsing HTTP.
        if self.raw_requestline.startswith(b"t3 "):
            self.close_connection = True
            # Drain the rest of the handshake, up to the terminating blank line.
            while True:
                line = self.rfile.readline(1024)
                if not line or line in (b"\n", b"\r\n"):
                    break
            if MODE != "vuln_console":
                self.wfile.write(
                    ("HELO:%s.false\nAS:2048\nHL:19\nMS:10000000\n\n" % VERSION).encode()
                )
                self.wfile.flush()
            return False
        return super().parse_request()

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if MODE != "patched" and path == "/console/login/LoginForm.jsp":
            self._send(200, LOGIN_PAGE, "text/html; charset=UTF-8")
        else:
            self._send(404, "<html><body><h1>Error 404--Not Found</h1></body></html>", "text/html")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
