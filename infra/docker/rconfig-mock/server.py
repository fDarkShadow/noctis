#!/usr/bin/env python3
"""Mock rConfig — CVE-2019-16662 unauthenticated command injection.

Vuln mode: a GET to install/lib/ajaxHandlers/ajaxServerSettingsChk.php whose
rootUname parameter contains a `;` shell separator "executes" the injected
command and reflects its output (uid=/gid=). Patched mode: the installer
handler is absent (404).
"""
import os
import ssl
import threading
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("RCONFIG_MODE", "patched") == "vuln"

CMD_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"


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
        parts = urlsplit(self.path)
        if parts.path.endswith("/install/lib/ajaxHandlers/ajaxServerSettingsChk.php"):
            if not VULN_MODE:
                self._send(404, "Not Found")
                return
            root_uname = parse_qs(parts.query).get("rootUname", [""])[0]
            # A ; shell separator injects a command whose output is reflected.
            if ";" in root_uname:
                self._send(200, f"Settings check...\n{CMD_OUTPUT}")
            else:
                self._send(200, "Settings check OK")
            return
        self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
