#!/usr/bin/env python3
# Mock for D-Link DNS-320 ShareCenter NAS — CVE-2020-25506
# unauthenticated OS command injection in /cgi-bin/system_mgr.cgi (f_ntp_server).
#
# Modes (DNS320_MODE env):
#   vuln    — the f_ntp_server value is evaluated by a tiny shell simulator that
#             performs command substitution ($() and backticks) and the inert
#             `echo` builtin, then reflects the RESULT. A collapse payload such
#             as `echo NOCTIS$()<tok>` therefore comes back as the joined
#             NOCTIS<tok>, exactly as a real vulnerable device would.
#   patched — the request is rejected (403); f_ntp_server is never evaluated.
#   reflect — a "cheating" device that echoes the RAW f_ntp_server value back
#             without any shell evaluation ($() stays intact). Used to prove the
#             detection keys on genuine collapse, not on reflection.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from mocklib import serve

MODE = os.environ.get("DNS320_MODE", "patched")
VULN_MODE = MODE == "vuln"
REFLECT_MODE = MODE == "reflect"


def _run_cmd(cmd):
    """Evaluate a single (already substitution-resolved) command. Only the inert
    `echo` builtin is honoured; anything else yields empty output."""
    cmd = cmd.strip()
    if cmd.startswith("echo"):
        return cmd[4:].strip()
    return ""


def sh_eval(s):
    """Minimal shell command-substitution evaluator: resolve $() then backticks,
    innermost first. Empty substitution ($()) collapses to the empty string."""
    guard = 0
    # $(...) — innermost (no nested parens inside the match)
    while guard < 100:
        m = re.search(r"\$\(([^()]*)\)", s)
        if not m:
            break
        s = s[: m.start()] + _run_cmd(sh_eval(m.group(1))) + s[m.end():]
        guard += 1
    # `...` — innermost
    while guard < 200:
        m = re.search(r"`([^`]*)`", s)
        if not m:
            break
        s = s[: m.start()] + _run_cmd(sh_eval(m.group(1))) + s[m.end():]
        guard += 1
    return s


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

    def do_POST(self):
        if self.path.split("?")[0] != "/cgi-bin/system_mgr.cgi":
            self._send(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw, keep_blank_values=True)
        cmd = (params.get("cmd", [""])[0])
        f_ntp_server = (params.get("f_ntp_server", [""])[0])

        if cmd != "cgi_ntp_time":
            self._send(200, "<xml><result>fail</result></xml>", "text/xml")
            return

        if VULN_MODE:
            # Vulnerable: f_ntp_server flows into a shell invocation.
            resolved = sh_eval(f_ntp_server)
            self._send(
                200,
                "<?xml version=\"1.0\"?>\n<config>\n  <result>success</result>\n"
                "  <ntp_server>%s</ntp_server>\n</config>\n" % resolved,
                "text/xml",
            )
        elif REFLECT_MODE:
            # Cheating device: reflects the RAW value, no shell evaluation.
            self._send(
                200,
                "<?xml version=\"1.0\"?>\n<config>\n  <result>success</result>\n"
                "  <ntp_server>%s</ntp_server>\n</config>\n" % f_ntp_server,
                "text/xml",
            )
        else:
            # Patched: request rejected, f_ntp_server never evaluated.
            self._send(403, "Forbidden")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
