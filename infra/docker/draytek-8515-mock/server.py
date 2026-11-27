#!/usr/bin/env python3
# DrayTek Vigor mock for CVE-2020-8515 (unauthenticated OS command injection
# via the keyPath parameter of /cgi-bin/mainfunction.cgi).
#
# Vuln mode faithfully emulates the injectable path: it URL-decodes the posted
# keyPath, applies the minimal shell transforms the real device would (${IFS}
# field splitting and $() command substitution), and when the result is an
# `echo <arg>` it returns <arg> as command output. It fabricates NO fixed
# marker of its own — whatever token the scanner injects is what comes back,
# exactly as a vulnerable shell would behave.
#
# Patched mode serves the same reachable endpoint but never evaluates keyPath;
# it returns a static login page, so the injected marker never appears.
import os
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("DRAYTEK_MODE", "patched") == "vuln"

LOGIN_PAGE = (
    "<html><head><title>Vigor Login</title></head>"
    "<body><form name=\"loginform\" action=\"/cgi-bin/mainfunction.cgi\" "
    "method=\"post\"><input name=\"loginUser\"><input name=\"loginPwd\" "
    "type=\"password\"></form></body></html>"
)


def emulate_shell(key_path):
    """Minimal emulation of how a vulnerable Vigor shell would process the
    quote-escaped keyPath. Returns the stdout of an injected `echo`, or None."""
    # ${IFS} is the shell field separator (space); $() with no command
    # substitutes to the empty string. A real vulnerable device collapses both.
    s = key_path.replace("${IFS}", " ").replace("$()", "")
    for raw in s.splitlines():
        line = raw.strip().strip("'").strip()
        if line.startswith("echo "):
            return line[len("echo "):].strip()
    return None


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
        if self.path.split("?")[0] != "/cgi-bin/mainfunction.cgi":
            self._send(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = parse_qs(raw, keep_blank_values=True)
        action = params.get("action", [""])[0]
        key_path = params.get("keyPath", [""])[0]

        if not VULN_MODE:
            # Patched firmware: endpoint still reachable, keyPath not evaluated.
            self._send(200, LOGIN_PAGE)
            return

        if action == "login" and key_path:
            out = emulate_shell(key_path)
            if out is not None:
                # Command output is returned inline, exactly as the injected
                # echo produced it (NOCTIS<token>). Marker is computed from the
                # request, never hardcoded here.
                body = "<html><body>Vigor\n" + out + "\n</body></html>"
                self._send(200, body)
                return

        # Fallthrough: normal login handling (no injection present).
        self._send(200, LOGIN_PAGE)

    def do_GET(self):
        if self.path.split("?")[0] == "/cgi-bin/mainfunction.cgi":
            self._send(200, LOGIN_PAGE)
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
