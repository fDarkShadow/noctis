#!/usr/bin/env python3
# Inert string-simulation mock for CVE-2021-44077 (Zoho ManageEngine
# ServiceDesk Plus unauthenticated file-upload RCE).
#
# It does NO real work: no subprocess, no os.system/exec, no file write to a
# web root, no code execution. The "upload" simply extracts the nonce text out
# of the multipart body and stashes it in an in-memory dict keyed by filename;
# the "retrieve" serves that stored text back. This reproduces the pre-auth
# upload+retrieve primitive the detection feed exercises, and nothing else.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("MANAGEENGINE_MODE", "patched") == "vuln"

# In-memory store of "uploaded" file contents, keyed by filename. Pure string
# state — never touches disk, never executed.
UPLOADS = {}

# Pull filename="..." and the raw part body out of a simple multipart/form-data.
_FILENAME_RE = re.compile(r'filename="([^"]+)"')


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    @staticmethod
    def _parse_multipart(raw):
        """Return (filename, content) extracted from a trivial multipart body."""
        m = _FILENAME_RE.search(raw)
        if not m:
            return None, None
        filename = m.group(1)
        # Part body = text between the blank line after the headers and the
        # trailing boundary. Keep it dead simple — this is string parsing only.
        idx = raw.find("\r\n\r\n", m.end())
        if idx < 0:
            return filename, None
        rest = raw[idx + 4:]
        end = rest.find("\r\n--")
        content = rest if end < 0 else rest[:end]
        return filename, content

    def do_GET(self):
        # Retrieve a previously "uploaded" sentinel from the web root.
        if self.path.startswith("/fileupload/"):
            name = self.path[len("/fileupload/"):]
            if VULN_MODE and name in UPLOADS:
                self._send(200, UPLOADS[name], "text/plain")
            else:
                # Patched: nothing persisted / not served.
                self._send(404, "Not Found")
            return
        if self.path.startswith("/RestAPI/"):
            if VULN_MODE:
                self._send(200, '{"operation":{"name":"ImportTechnicians"}}',
                           "application/json")
            else:
                self._send(403, "Unauthorized")
            return
        self._send(404, "Not Found")

    def do_POST(self):
        raw = self._read_body()
        if self.path.startswith("/RestAPI/ImportTechnicians"):
            if VULN_MODE:
                # Unauthenticated upload accepted — stash the sentinel text.
                filename, content = self._parse_multipart(raw)
                if filename and content is not None:
                    UPLOADS[filename] = content
                self._send(
                    200,
                    '{"operation":{"name":"ImportTechnicians",'
                    '"result":{"status":"Success","message":"imported"}}}',
                    "application/json",
                )
            else:
                # Patched: the security filter no longer fails open on /RestAPI.
                self._send(403, "Unauthorized")
            return
        self._send(404, "Not Found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
