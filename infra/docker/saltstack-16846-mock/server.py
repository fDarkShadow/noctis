#!/usr/bin/env python3
"""Mock for SaltStack salt-api CVE-2020-16846 (unauthenticated shell injection).

Pure string/regex simulation of salt-ssh — NO real command, SSH, file or network
execution ever happens. The vuln branch simulates the shell's empty-command-
substitution collapse (`$()` -> "") with str.replace and reflects the collapsed
output; the patched branch rejects the request at the eauth layer.

Modes (SALTSTACK_MODE):
  vuln             real behaviour: collapse `$()` and reflect the command output
  patched          eauth rejects — no injection, no reflection
  reflect_intact   adversarial: reflect the payload verbatim ($() NOT collapsed)
  constant_marker  adversarial: always return a fixed NOCTIS<hex> (no per-run echo)
Only `vuln` and `patched` are shipped (Dockerfile.vuln / Dockerfile.patched); the
two adversarial modes exist so the detection feed can be proven free of false
positives.
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("SALTSTACK_MODE", "patched")

# Capture the argument of an `echo` command anywhere in the submitted ssh options.
ECHO_RE = re.compile(r"echo\s+([A-Za-z0-9$()_-]+)")
# A constant, request-independent marker for the "cheating" mock.
CONSTANT_MARKER = "NOCTIS0123456789abcdef0123456789abcdef"[:38]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # salt-api root advertises the available clients.
        if self.path == "/":
            self._send_json(200, {"clients": ["local", "ssh", "runner", "wheel"],
                                  "return": "Welcome"})
        else:
            self._send_json(404, {"return": ["Not found"]})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        if self.path != "/run":
            self._send_json(404, {"return": ["Not found"]})
            return

        if MODE == "patched":
            # Fixed version: external auth is enforced before any ssh command is
            # built, so the crafted request never reaches a shell.
            self._send_json(401, {"return": ["Could not authenticate using "
                                             "provided credentials"]})
            return

        if MODE == "constant_marker":
            # Cheating mock: returns a marker shape that satisfies the regex but is
            # NOT derived from this run's token.
            self._send_json(200, {"return": [{"local": CONSTANT_MARKER + "\n"}]})
            return

        m = ECHO_RE.search(raw)
        if not m:
            # No injectable echo primitive -> nothing to reflect (benign request).
            self._send_json(200, {"return": [{"local": ""}]})
            return

        arg = m.group(1)
        if MODE == "reflect_intact":
            # Cheating mock: reflects the payload verbatim WITHOUT collapsing $().
            output = arg
        else:  # vuln
            # Simulate the shell: an empty command substitution $() expands to
            # nothing, so the two halves of the echo argument become contiguous.
            output = arg.replace("$()", "")

        self._send_json(200, {"return": [{"local": output + "\n"}]})


if __name__ == "__main__":
    serve(Handler, HTTPServer)
