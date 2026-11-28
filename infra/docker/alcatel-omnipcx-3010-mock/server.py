#!/usr/bin/env python3
"""Mock Alcatel-Lucent OmniPCX Enterprise masterCGI endpoint — CVE-2007-3010.

Vuln mode SIMULATES (never executes) the shell command injection in the `user`
parameter of /cgi-bin/masterCGI?ping=nomip, using pure string/regex operations:

  * the injection is only honoured when the attacker's `user` value both breaks
    out with a leading `;` AND carries the empty command-substitution primitive
    `$()` — i.e. a real shell is required to collapse it;
  * the simulated shell drops every empty `$()` (command substitution of nothing
    yields the empty string) and `` `` `` backticks, then evaluates a leading
    `echo` and reflects its literal argument into the response body;
  * the reply always carries the real appliance's `<TITLE>master</TITLE>` chrome.

No command is ever run, no file is touched: the handler only rewrites strings,
so a detection that merely relied on reflection (payload echoed verbatim) or on
a canned marker would NOT match — only true `$()` collapse of the attacker's own
random token produces the contiguous marker.

Patched mode treats `user` as literal data: the ping diagnostic reports a plain
result and nothing from `user` is ever evaluated or reflected.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

from mocklib import serve  # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("ALCATEL_OMNIPCX_MODE", "patched") == "vuln"


def master_page(body):
    return (
        "<HTML><HEAD><TITLE>master</TITLE></HEAD><BODY>\n"
        "<H1>OmniPCX Enterprise</H1>\n"
        "<PRE>\n" + body + "\n</PRE>\n"
        "</BODY></HTML>\n"
    )


def simulate_shell(user_value):
    """Pure-string simulation of /bin/sh evaluating the injected `user` value.

    Returns the stdout the real masterCGI would reflect, or None when nothing
    is evaluated (so the benign/no-injection case produces no marker).
    """
    # A real injection breaks out of the intended command with `;` and relies on
    # the `$()` (or backtick) command-substitution primitive to assemble its
    # payload. Require both so verbatim-reflection cheats do not qualify.
    if ";" not in user_value:
        return None
    if "$(" not in user_value and "`" not in user_value:
        return None

    out = []
    for raw in user_value.split(";"):
        cmd = raw.strip()
        if not cmd.startswith("echo"):
            continue
        arg = cmd[4:].lstrip()
        # Command substitution of an empty command yields the empty string, so a
        # real shell collapses `$()` / `$( )` / `` `` `` to nothing. Pure regex.
        arg = re.sub(r"\$\(\s*\)", "", arg)
        arg = re.sub(r"`\s*`", "", arg)
        out.append(arg)
    if not out:
        return None
    return "\n".join(out)


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
        parsed = urlparse(self.path)
        if parsed.path != "/cgi-bin/masterCGI":
            self._send(404, master_page("Not found"))
            return

        qs = parse_qs(parsed.query, keep_blank_values=True)
        ping = qs.get("ping", [""])[0]
        user = unquote_plus(qs.get("user", [""])[0])

        if not VULN_MODE:
            # Patched: `user` is inert data, never evaluated or reflected.
            self._send(200, master_page("ping nomip: host alive"))
            return

        if ping != "nomip":
            self._send(200, master_page("ping: unknown mode"))
            return

        reflected = simulate_shell(user)
        if reflected is None:
            # No injection / benign user — plain diagnostic, no reflection.
            self._send(200, master_page("ping nomip: host alive"))
            return

        self._send(200, master_page("ping nomip for user " + reflected))

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)  # HTTP:80 + HTTPS:443 (cert from the base image)
