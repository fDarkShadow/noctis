#!/usr/bin/env python3
"""Mock for CVE-2019-16759 — vBulletin 5.0.0-5.5.4 unauthenticated RCE.

The vulnerable endpoint /ajax/render/widget_tabbedcontainer_tab_panel renders a
caller-chosen widget; `widget_php` makes real vBulletin evaluate the supplied PHP.

CYBER-SAFETY: this mock never runs PHP or a subprocess. It *simulates* the single
observable effect the detector relies on — `echo md5('<token>');` — purely with
Python's hashlib: it parses the string argument the caller passed to md5() inside
the `code` parameter and reflects hashlib.md5(arg).hexdigest(). No file writes, no
webshell, no eval. A constant-hash or verbatim-reflecting mock would not satisfy
the per-run token check, which is exactly the point.
"""
import hashlib
import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from mocklib import serve

VULN_MODE = os.environ.get("VBULLETIN_MODE", "patched") == "vuln"

# Matches  md5('ARG')  or  md5("ARG")  inside the decoded PHP `code` payload.
MD5_CALL = re.compile(r"md5\(\s*['\"]([^'\"]*)['\"]\s*\)")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html; charset=UTF-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def do_GET(self):
        # A patched/benign landing page; nothing exploitable here.
        self._send(200, "<html><body>vBulletin</body></html>")

    def do_POST(self):
        if self.path != "/ajax/render/widget_tabbedcontainer_tab_panel":
            self._send(404, "Not Found")
            return

        raw = self._body()
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        template = params.get("subWidgets[0][template]", [""])[0]
        code = params.get("subWidgets[0][config][code]", [""])[0]

        if VULN_MODE and template == "widget_php" and code:
            # Simulate the ONE effect we detect on: evaluate echo md5('<arg>');
            # by computing md5 over the literal argument the PHP passes to md5().
            m = MD5_CALL.search(code)
            if m is not None:
                arg = m.group(1)
                digest = hashlib.md5(arg.encode()).hexdigest()
                # NOCTIS_VBULLETIN_CONFIRMED marks the vulnerable rendering path.
                self._send(200, "NOCTIS_VBULLETIN_CONFIRMED\n" + digest)
                return
            # PHP that doesn't call md5() produces no reflected digest.
            self._send(200, "")
            return

        # Patched: the widget renderer refuses untrusted widget_php templates.
        self._send(200, '{"errors":[["widget_php_disabled"]]}',
                   ct="application/json")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
