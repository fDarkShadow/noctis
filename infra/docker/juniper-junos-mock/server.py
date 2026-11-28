#!/usr/bin/env python3
# Mock for Juniper Junos OS J-Web — CVE-2023-36845 (PHP external variable
# modification via PHPRC). Models the SAFE detection differential only.
#
# The feed sends an unauthenticated request with `?PHPRC=/dev/fd/0` and a benign
# php.ini body that toggles diagnostic directives (display_errors / error_reporting).
# The ONLY distinguishing effect is whether PHP's own diagnostics leak into the
# response:
#   - vuln    : J-Web honours the injected php.ini → diagnostics leak (200 + notice)
#   - patched : J-Web ignores PHPRC → normal J-Web login page (200, no diagnostics)
#   - benign request (no PHPRC injection) on the vuln mock → normal page, no leak
#
# No code execution, no file read/write is modelled — the mock never honours
# auto_prepend_file or reads /etc/passwd; it only mirrors the inert config toggle.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("JUNOS_MODE", "patched") == "vuln"

# A normal, unmodified J-Web login page (no PHP diagnostics).
LOGIN_PAGE = (
    "<html><head><title>Juniper Web Device Manager</title></head>"
    "<body><div id=\"jweb-login\">Juniper Networks J-Web</div>"
    "<form action=\"/?PHPSESSID=\" method=\"post\"></form></body></html>"
)

# What a vulnerable J-Web emits once the injected php.ini forces display_errors on:
# PHP's own startup/runtime diagnostics surface in the response body. This is the
# genuine behavioural differential — not a planted token.
PHP_DIAGNOSTIC = (
    "<br />\n<b>Notice</b>:  Undefined variable: user in "
    "<b>/usr/jail/html/webauth_operation.php</b> on line 24<br />\n"
    "<br />\n<b>Warning</b>:  session_start(): Cannot start session in "
    "<b>/usr/jail/html/index.php</b> on line 3<br />\n"
)


def _wants_injection(path, body):
    """True when the request carries the PHPRC env-var injection and an inert
    php.ini body that enables diagnostic output."""
    if "PHPRC=" not in path:
        return False
    low = body.lower()
    return "display_errors" in low or "error_reporting" in low


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Juniper J-Web")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return ""
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def do_GET(self):
        self._send(200, LOGIN_PAGE)

    def do_POST(self):
        body = self._read_body()
        if VULN_MODE and _wants_injection(self.path, body):
            # Vulnerable J-Web honours the attacker-controlled php.ini: PHP's own
            # diagnostics now leak into the page. Benign, inert, no code executed.
            self._send(200, LOGIN_PAGE + PHP_DIAGNOSTIC)
        else:
            # Patched J-Web ignores PHPRC; a benign (non-injection) request on the
            # vuln mock lands here too — either way, no diagnostics leak.
            self._send(200, LOGIN_PAGE)


if __name__ == "__main__":
    serve(Handler, HTTPServer)
