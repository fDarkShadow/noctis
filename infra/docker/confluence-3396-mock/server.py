#!/usr/bin/env python3
"""Mock Atlassian Confluence — CVE-2019-3396 Widget Connector path traversal.

VULN_MODE: the Widget Connector preview endpoint resolves the `_template`
parameter without sanitising `../`, so a traversal to /etc/passwd is reflected
as genuine file contents (as a real vulnerable Confluence < 6.6.12 does).

Patched: the traversal is rejected and a benign Velocity/400 error is returned
with no file contents.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CONFLUENCE_MODE", "patched") == "vuln"

# Realistic /etc/passwd contents a vulnerable target would reflect.
ETC_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "confluence:x:2001:2001::/home/confluence:/bin/bash\n"
)

PREVIEW_PATH = "/rest/tinymce/1/macro/preview"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == PREVIEW_PATH:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            # The Widget Connector traversal keys off a `_template` value that
            # walks out of the Velocity templates directory to a target file.
            is_traversal = '"_template"' in body and "../" in body
            if VULN_MODE and is_traversal:
                # Vulnerable: the requested file is resolved and reflected.
                self._send(200, ETC_PASSWD)
            else:
                # Patched: traversal blocked, generic Velocity render error.
                err = (
                    '{"errorMessages":["Unable to render the macro: '
                    'template could not be resolved"],"successfulMacros":[]}'
                )
                self._send(400, err, ct="application/json")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
