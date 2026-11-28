#!/usr/bin/env python3
"""Inert string-simulation mock for Microsoft OMI (OMIGOD) — CVE-2021-38647.

Vuln mode   : the WSMan /wsman SOAP endpoint accepts a request that carries NO
              HTTP Authorization header (the auth bypass) and simulates running
              the embedded `echo` command AS A SHELL WOULD — purely by string
              manipulation: it collapses the empty command substitution `$()` to
              nothing and echoes the resulting stdout back inside a SOAP element.
              There is NO subprocess / os.system / exec / file I/O: the "shell"
              is a string transform, so the mock cannot actually run anything.

Patched mode: the same no-auth request is rejected with HTTP 401 (auth is now
              required), and nothing is ever echoed.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("OMI_MODE", "patched") == "vuln"

COMMAND_RE = re.compile(r"<p:command>(.*?)</p:command>", re.DOTALL)


def simulate_echo(command):
    """Emulate `echo <arg>` for the inert probe, by string transform only.

    A real /bin/sh would first expand the empty command substitution `$()` to
    the empty string, then echo the argument. We reproduce exactly that one
    behaviour on the string — no shell, no process is ever spawned.
    """
    command = command.strip()
    if not command.startswith("echo "):
        return None
    arg = command[len("echo "):]
    # Collapse empty command substitution(s) the way a shell would.
    arg = re.sub(r"\$\(\s*\)", "", arg)
    return arg


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/soap+xml;charset=UTF-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") != "/wsman":
            self._send(404, "Not found", ct="text/plain")
            return

        # Patched OMI requires authentication for WSMan requests.
        if not VULN_MODE:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Basic realm=\"wsman\"")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Vulnerable OMI: a request with NO Authorization header is honoured as
        # root. If one IS supplied we still answer (harmless), but the bypass is
        # proven by the no-auth case the feed sends.
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        m = COMMAND_RE.search(raw)
        stdout = ""
        if m:
            simulated = simulate_echo(m.group(1))
            if simulated is not None:
                stdout = simulated

        resp = (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:p="http://schemas.microsoft.com/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">'
            "<s:Body><p:ExecuteShellCommand_OUTPUT>"
            "<p:ReturnCode>0</p:ReturnCode>"
            "<p:StdOut>" + stdout + "\n</p:StdOut>"
            "<p:StdErr></p:StdErr>"
            "</p:ExecuteShellCommand_OUTPUT></s:Body></s:Envelope>"
        )
        self._send(200, resp)

    def do_GET(self):
        # OMI answers WSMan on POST only; anything else is a plain 404.
        self._send(404, "Not found", ct="text/plain")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
