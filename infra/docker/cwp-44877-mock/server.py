#!/usr/bin/env python3
# Mock for CVE-2022-44877 — Control Web Panel unauthenticated RCE via the
# `login` parameter of /login/index.php.
#
# Both modes identify as CWP (so the feed's fingerprint gate passes on both).
# The differential is faithful to the real bug:
#   vuln    — the login value is passed to a shell context, so an arithmetic
#             expansion `$(( A + B ))` embedded in it is EVALUATED (we compute
#             the sum here; no eval/shell is actually invoked), and the reflected
#             value becomes `<marker><A+B>`.
#   patched — the value is handled literally (no shell), so `$(( A + B ))` is
#             reflected verbatim and the evaluated token never appears.
import os
import re
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("CWP_MODE", "patched") == "vuln"

# Emulate shell arithmetic expansion of `$(( <int> + <int> ))` without a shell:
# parse the two integers and substitute their sum, leaving surrounding text.
ARITH = re.compile(r"\$\(\(\s*(\d+)\s*\+\s*(\d+)\s*\)\)")


def eval_arith(value):
    return ARITH.sub(lambda m: str(int(m.group(1)) + int(m.group(2))), value)


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

    def _handle(self):
        parsed = urlparse(self.path)
        if parsed.path != "/login/index.php":
            self._send(404, "Not found")
            return

        login = parse_qs(parsed.query).get("login", [""])[0]
        if not login:
            self._send(200, "<html><title>Control WebPanel</title>cwp - Login</html>")
            return

        if VULN_MODE:
            # Login value reaches a shell context: the arithmetic expansion is
            # evaluated, so the reflected entry carries the computed sum.
            reflected = eval_arith(login)
            body = (
                "<html><title>Control WebPanel</title>\n"
                "Login Redirect.\n"
                "entry=%s\n"
                "</html>" % reflected
            )
            self._send(200, body)
        else:
            # Patched: handled literally, no shell evaluation.
            body = (
                "<html><title>Control WebPanel</title>\n"
                "Login failed.\n"
                "entry=%s\n"
                "</html>" % html.escape(login)
            )
            self._send(200, body)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        # Drain the request body (ignored; the injection is in the query).
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._handle()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
