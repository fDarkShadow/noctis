#!/usr/bin/env python3
# Mock for NETGEAR WNAP320 ProSafe AP command injection (CVE-2016-1555).
#
# Vulnerable firmware passes the `macAddress` POST parameter of
# /boardDataWW.php to a device shell without sanitisation. This mock faithfully
# reproduces the vulnerable code path by evaluating the injected shell string:
# an empty `$()` command substitution collapses to nothing (as a real shell
# does) and the inert `echo` argument is emitted. A reflecting / cheating mock
# that returned the raw request body would keep the `$()` separator and fail
# the detection; a patched device serves a benign static form and evaluates
# nothing.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from mocklib import serve

MODE = os.environ.get("WNAP320_MODE", "patched")
VULN_MODE = MODE == "vuln"
REFLECT_MODE = MODE == "reflect"   # cheating/reflecting mock — must NOT be detected

FORM = (
    "<html><head><title>NETGEAR WNAP320</title></head><body>"
    "<form action=\"/boardDataWW.php\" method=\"post\">"
    "<input name=\"macAddress\"><input name=\"reginfo\">"
    "<input type=\"submit\" name=\"writeData\" value=\"Submit\">"
    "</form></body></html>"
)


def eval_shell(cmd):
    """Inert simulation of the device shell for the injected macAddress.

    Only two behaviours are modelled, both inert: empty `$()` command
    substitution collapses to the empty string (what a real shell does), and
    an `echo <args>` command emits its (now joined) argument. No real command
    is run, no file is read or written.
    """
    # Collapse empty command substitutions: $() -> "" (shell behaviour).
    cmd = re.sub(r"\$\(\)", "", cmd)
    out = []
    for part in cmd.split(";"):
        part = part.strip()
        m = re.match(r"^echo\s+(.*)$", part)
        if m:
            out.append(m.group(1).strip())
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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", "replace") if length > 0 else ""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/boardDataWW.php"):
            self._send(200, FORM)
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/boardDataWW.php":
            self._send(404, "Not found", "text/plain")
            return
        body = self._read_body()
        mac = parse_qs(body, keep_blank_values=True).get("macAddress", [""])[0]

        if VULN_MODE:
            # Vulnerable: macAddress reaches the shell; evaluate it inertly.
            output = eval_shell(mac)
            self._send(200, "boardDataWW\n" + output + "\n", "text/plain")
        elif REFLECT_MODE:
            # Cheating mock: reflects the raw injected value verbatim (with the
            # $() separator intact) without shell evaluation — must score 0.
            self._send(200, "macAddress=" + mac + "\n", "text/plain")
        elif MODE == "constant":
            # Cheating mock: emits a constant NOCTIS<hex> marker that is not the
            # per-run token — matches the regex but fails the stridx condition.
            self._send(200, "NOCTIS00000000000000000000000000000000\n", "text/plain")
        else:
            # Patched: benign static form, no evaluation.
            self._send(200, FORM)


if __name__ == "__main__":
    http_port = int(os.environ.get("HTTP_PORT", "80"))
    https_port = int(os.environ.get("HTTPS_PORT", "443"))
    serve(Handler, HTTPServer, http_port=http_port, https_port=https_port)
