#!/usr/bin/env python3
"""Mock for CVE-2020-9054 — Zyxel NAS weblogin.cgi pre-auth OS command injection.

VULN_MODE simulates the vulnerable /cgi-bin/weblogin.cgi: the unauthenticated
`username` query parameter reaches a shell command unsanitised, so a single
quote closes the quoted username and the following `;...;` segments run as shell
commands. This mock emulates ONLY an inert `echo` with empty command
substitution `$()` — it never executes anything on the host and never reads any
file. The point of the detection is the command-substitution collapse: a real
shell evaluates the empty `$()` to the empty string and `echo` joins the halves,
so `echo NOCTIS$()<token>` prints the single string `NOCTIS<token>`. A patched
device returns the login form and never evaluates the parameter.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from mocklib import serve

VULN_MODE = os.environ.get("ZYXEL_MODE", "patched") == "vuln"

LOGIN_FORM = (
    "<html><head><title>Zyxel NAS Login</title></head>"
    "<body><form name=\"weblogin\" action=\"/cgi-bin/weblogin.cgi\" method=\"post\">"
    "<input name=\"username\"><input name=\"password\" type=\"password\">"
    "</form></body></html>"
)


def shell_eval(raw_username):
    """Inertly emulate the vulnerable `sh -c \"...username='<raw>'...\"`.

    A single quote in the value closes the shell literal; the regions that fall
    outside the original quotes are the injected command context. We support
    ONLY `echo` and collapse an EMPTY command substitution `$()` to the empty
    string, exactly as a real shell would. Anything with a non-empty `$(...)` or
    backticks is ignored — no host command is ever run.
    """
    outputs = []
    parts = raw_username.split("'")
    for i, segment in enumerate(parts):
        if i % 2 == 0:
            # still inside the original single-quoted username literal
            continue
        for cmd in segment.split(";"):
            cmd = cmd.strip()
            m = re.match(r"echo\s+(.*)$", cmd)
            if not m:
                continue
            arg = m.group(1)
            # Collapse the empty command substitution $() -> "" (shell semantics).
            arg = re.sub(r"\$\(\s*\)", "", arg)
            # Never evaluate a real (non-empty) substitution or backticks.
            if "$(" in arg or "`" in arg:
                continue
            outputs.append(arg)
    return outputs


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        parsed = urlparse(self.path)
        if parsed.path != "/cgi-bin/weblogin.cgi":
            self._send(404, "Not found")
            return

        if not VULN_MODE:
            # Patched: always serve the login form, never evaluate `username`.
            self._send(200, LOGIN_FORM, ct="text/html")
            return

        username = parse_qs(parsed.query).get("username", [""])[0]
        outputs = shell_eval(username)
        if outputs:
            # The injected echo ran: reflect its collapsed stdout, as the
            # vulnerable CGI does when the command output lands in the response.
            body = "\n".join(outputs) + "\n"
            self._send(200, body)
        else:
            # No injection (plain login attempt): behave like the login form.
            self._send(200, LOGIN_FORM, ct="text/html")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
