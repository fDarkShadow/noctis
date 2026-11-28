#!/usr/bin/env python3
# Mock for nostromo nhttpd CVE-2019-16278 (path-traversal → RCE via /bin/sh).
#
# VULN  : the "%0d"-encoded traversal path reaches /bin/sh; the POST body is
#         piped to an INERT shell simulator that evaluates `echo` lines and
#         collapses `$(...)` command substitutions (so the empty `$()` in the
#         detection payload disappears and the marker is joined contiguously).
#         Nothing on the host is executed — the simulator only mimics the shell.
# PATCH : the traversal path is rejected (404), exactly like nhttpd >= 1.9.7.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("NOSTROMO_MODE", "patched") == "vuln"

# nhttpd reaches the shell only for a path whose traversal uses the CR ("%0d")
# trick to climb above the docroot into an absolute binary path.
TRAVERSAL_RE = re.compile(r"\.%0d\.(?:/\.%0d\.)*/bin/sh", re.IGNORECASE)


def sh_eval(script):
    """Inert shell simulator: run `echo` lines, collapse `$(...)` substitutions.

    This is NOT a real shell — it never spawns a process or touches the host.
    It reproduces just enough of /bin/sh semantics that a genuine command
    substitution (`$()`) evaluates away, which is what the detection relies on.
    A server that merely reflected the raw body would leave the `$()` intact.
    """
    out = []
    for raw in script.split("\n"):
        line = raw.strip()
        if not line or not line.startswith("echo"):
            continue
        arg = line[4:].strip()
        # Collapse innermost $(...) by recursively evaluating the inner command.
        while True:
            m = re.search(r"\$\(([^()]*)\)", arg)
            if not m:
                break
            arg = arg[:m.start()] + sh_eval(m.group(1)) + arg[m.end():]
        out.append(arg)
    return "\n".join(out)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Server", "nostromo 1.9.6")
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(200, "nostromo nhttpd 1.9.6\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        # self.path keeps the raw, un-decoded request target including "%0d".
        if VULN_MODE and TRAVERSAL_RE.search(self.path):
            self._send(200, sh_eval(body))
        else:
            self._send(404, "not found\n")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
