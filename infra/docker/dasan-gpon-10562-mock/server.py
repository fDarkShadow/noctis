#!/usr/bin/env python3
# Mock for Dasan GPON Home Router command injection (CVE-2018-10562).
#
# Two-request chain, exactly like the real device:
#   1. POST /GponForm/diag_Form?images/  — the ping diagnostic form. The
#      `dest_host` field is passed to a shell; a `` `...` `` backtick command
#      substitution is executed and its stdout stored as the diagnostic output.
#   2. GET  /diag.html                   — renders the stored diagnostic output.
#
# Vuln mode simulates the shell PURELY with string/regex ops (no real command
# execution, no file access, no network): it collapses empty `$()` command
# substitutions to the empty string and evaluates a leading `echo`. So an
# injected `echo NOCTIS$()<tok>` collapses to the CONTIGUOUS marker
# "NOCTIS<tok>" — only because the `$()` collapse primitive is genuinely
# applied. A payload that lacks the collapse primitive, or a server that
# reflects the request verbatim, never produces a contiguous marker.
#
# Patched mode treats dest_host as a literal hostname (no shell, no backtick
# execution), so the injected echo is never evaluated and no marker appears.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("DASANGPON_MODE", "patched") == "vuln"

# Diagnostic output produced by the last diag_Form POST, rendered by /diag.html.
LAST_DIAG = {"out": ""}


def _exec_cmd(cmd):
    """Simulate a shell command's stdout (string ops only, inert)."""
    # Command substitution of an empty command, $() , expands to nothing.
    # Collapse every $(...) to the empty string, as a real shell would.
    collapsed = re.sub(r"\$\([^()]*\)", "", cmd).strip()
    m = re.match(r"echo\s+(.*)", collapsed)
    if m:
        return m.group(1).strip()
    return ""


def _run_dest_host(dest):
    """Device behaviour: dest_host goes through a shell; backtick command
    substitutions are executed and their stdout is the diagnostic output."""
    outs = [_exec_cmd(c) for c in re.findall(r"`([^`]*)`", dest)]
    return "\n".join(o for o in outs if o)


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
        if self.path == "/GponForm/diag_Form?images/":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            m = re.search(r"dest_host=([^&]*)", body)
            dest = m.group(1) if m else ""
            if VULN_MODE:
                # Unauthenticated command injection: the shell runs dest_host.
                result = _run_dest_host(dest)
                LAST_DIAG["out"] = result if result else "ping: unknown host"
            else:
                # Patched: dest_host is a literal hostname, no shell execution.
                LAST_DIAG["out"] = "ping: bad address (invalid host)"
            # The device redirects the browser to the results page.
            self._send(200, "<html><body>diagnostic started</body></html>")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/diag.html":
            page = (
                "<html><head><title>GPON Diagnostics</title></head><body>"
                "<h3>PING</h3><textarea id='diag_output' rows='10' cols='80'>"
                + LAST_DIAG["out"]
                + "</textarea></body></html>"
            )
            self._send(200, page)
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
