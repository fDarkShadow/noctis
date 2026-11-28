#!/usr/bin/env python3
# Inert mock for CVE-2020-14750 (Oracle WebLogic Server administration console
# authentication bypass via an encoded path-traversal prefix). Pure string
# simulation of the console auth filter's fails-open behaviour — NO subprocess,
# os.system, exec, eval or file I/O, and no command execution of any kind. The
# "privileged" page only echoes the request's nonce parameter; nothing on the
# request is ever evaluated or run.
import os
import re
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

from mocklib import serve

VULN_MODE = os.environ.get("WEBLOGIC_MODE", "patched") == "vuln"

# An encoded traversal token in the path (single- or double-encoded ../ or a
# literal ..). This is what lets the console auth filter mistake the request for
# a /console/css/ static asset — the essence of the bypass.
_TRAVERSAL = re.compile(r"%252e|%252f|%2e|%2f|\.\.", re.IGNORECASE)

_LOGIN_BODY = (
    "<html><head><title>Oracle WebLogic Server Administration Console</title>"
    "</head><body><h1>Sign In</h1><form action='/console/j_security_check' "
    "method='post'>Please sign in to access the WebLogic Server console."
    "</form></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", cookie=None, location=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        if location is not None:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def _login_redirect(self):
        # Intact filter: redirect any console.portal request to the login form.
        self._send(
            302,
            _LOGIN_BODY,
            location="/console/login/LoginForm.jsp",
        )

    def _handle(self):
        parts = urlsplit(self.path)
        raw_path = parts.path
        is_console_portal = "console.portal" in raw_path
        has_traversal = bool(_TRAVERSAL.search(raw_path))

        if not is_console_portal:
            # Anything else: a bland WebLogic-ish 404.
            self._send(404, "<html><body>Error 404--Not Found</body></html>")
            return

        if not (VULN_MODE and has_traversal):
            # Patched (filter intact) for any path, and vuln for the non-traversal
            # control path: the auth filter catches console.portal and redirects
            # to the login form without reaching the privileged handler.
            self._login_redirect()
            return

        # Vulnerable + encoded traversal prefix: the auth filter failed open and
        # the request reached the privileged console.portal handler, which echoes
        # the request's nonce parameter and establishes a console session cookie.
        nonce = parse_qs(parts.query).get("nonce", [""])[0]
        # Keep only characters a real reflected parameter would preserve here;
        # purely defensive, the engine only ever sends [A-Za-z0-9].
        nonce = re.sub(r"[^A-Za-z0-9]", "", nonce)[:64]
        session = secrets.token_hex(16).upper()
        body = (
            "<html><head><title>Oracle WebLogic Server Administration Console"
            "</title></head><body>"
            "<div id='console-portal'>WebLogic Server Administration Console - Home</div>"
            "<form name='consoleForm' action='/console/console.portal'>"
            f"<input type='hidden' name='nonce' value='{nonce}'/>"
            "</form></body></html>"
        )
        self._send(
            200,
            body,
            cookie=f"ADMINCONSOLESESSION={session}; path=/console; HttpOnly",
        )

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
