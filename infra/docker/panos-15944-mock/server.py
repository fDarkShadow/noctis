#!/usr/bin/env python3
"""Inert mock for CVE-2017-15944 (Palo Alto PAN-OS unauthenticated RCE).

PURE string/regex simulation of the auth-bypass + command-injection chain — NO
subprocess, os.system, exec, eval, file I/O or sockets of our own. The vuln mode
reproduces the genuine per-run consequence of the probe (a real shell collapsing
an empty command substitution `$()`), so detection depends on the live token, not
on a hardcoded marker. The patched mode is inert: it reflects the request verbatim
(the `$()` stays, so the two marker halves never become contiguous) and no
detection step fires.
"""
import os
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PANOS_15944_MODE", "patched") == "vuln"

# The vulnerable management endpoint exposed by the auth bypass.
ENDPOINT = "/esp/cms_changeDeviceContext.esp"


def simulate_shell_echo(decoded_query):
    """Simulate a real shell running the injected `echo ...` command.

    Faithful to what the PAN-OS management shell does with the injected
    `device=...:a'";echo NOCTIS$()<token>;"` payload: the shell executes the
    echo, and the empty command substitution `$()` expands to the empty string,
    so `NOCTIS$()<token>` becomes the contiguous `NOCTIS<token>`. Pure string
    rewriting — no command is ever run.
    """
    # Empty command substitution expands to nothing.
    collapsed = decoded_query.replace("$()", "")
    return collapsed


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
        # self.path is the raw, still-encoded request target from the socket.
        raw = self.path
        if ENDPOINT not in raw:
            self._send(404, "Not found")
            return

        # Decode the percent-encoded breakout payload exactly as the backend
        # would before it reaches the shell context (%27 -> ', %22 -> ", etc.).
        decoded = unquote(raw)

        if VULN_MODE:
            # Auth bypass: the endpoint is reachable unauthenticated and the
            # injected command runs. Simulate the shell: collapse `$()`.
            executed = simulate_shell_echo(decoded)
            body = (
                "<html><body>"
                "@start@Success@end@ "
                "NOCTIS_PANOS_CONFIRMED "
                "device-context-output: " + executed +
                "</body></html>"
            )
            self._send(200, body)
        else:
            # Patched: the command is NOT executed. The request is reflected
            # verbatim, so the empty `$()` is preserved between the marker halves
            # and no contiguous NOCTIS<token> ever appears. Benign result.
            body = (
                "<html><body>"
                "@start@Error@end@ "
                "invalid device context request: " + decoded +
                "</body></html>"
            )
            self._send(200, body)

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
