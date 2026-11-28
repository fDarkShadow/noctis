#!/usr/bin/env python3
# NUUO NVRmini CVE-2018-14933 mock — unauthenticated command injection in
# upgrade_handle.php (writeuploaddir -> uploaddir). INERT: the "vulnerable"
# mode is a PURE STRING SIMULATION of a POSIX shell collapsing an empty
# command substitution `$()`. There is NO subprocess / os.system / exec /
# eval / file I/O of any kind — nothing from the request is ever executed.
import os
import re
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("NUUO_MODE", "patched") == "vuln"


def simulate_echo(arg):
    """Pure string model of `echo <arg>` under a shell: empty command
    substitutions `$()` / `` `` `` collapse to nothing, joining neighbours.
    Never executes anything."""
    return arg.replace("$()", "").replace("``", "")


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
        if parsed.path == "/upgrade_handle.php":
            qs = parse_qs(parsed.query, separator="&")
            cmd = qs.get("cmd", [""])[0]
            uploaddir = qs.get("uploaddir", [""])[0]
            if VULN_MODE and cmd == "writeuploaddir":
                # Vulnerable firmware injects `uploaddir` verbatim into a shell
                # command line. Model the single-quote breakout ';<cmd>;' and
                # the shell's $() collapse purely as string operations.
                injected = ""
                m = re.search(r"';(.*);'", uploaddir)
                if m:
                    injected = m.group(1)
                echoed = ""
                em = re.match(r"\s*echo\s+(.*)", injected)
                if em:
                    echoed = simulate_echo(em.group(1))
                body = (
                    "uid=0(root) gid=0(root) groups=0(root)\n"
                    + echoed
                    + "\nNOCTIS_NUUO_CONFIRMED\n"
                )
                self._send(200, body)
            else:
                # Patched firmware: parameter is sanitised / endpoint locked.
                self._send(404, "Not found")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
