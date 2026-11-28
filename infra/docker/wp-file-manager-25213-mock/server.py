#!/usr/bin/env python3
"""Mock for CVE-2020-25213 — WordPress File Manager plugin unauthenticated upload.

VULN mode: the bundled elFinder connector.minimal.php is reachable without auth and
accepts the elFinder cmd=upload request, storing the uploaded file and serving it back
from lib/files/ — the vulnerable condition the feed confirms via write-then-read.

PATCHED mode: the connector is access-restricted (403) and the file store returns 404,
so the write-then-read differential fails and no finding is produced.

The mock stores and echoes back whatever bytes the client uploads; it never fabricates a
detection marker — the feed matches the scanner-generated token it itself uploaded.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("WPFM_MODE", "patched") == "vuln"

CONNECTOR = "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
FILES_PREFIX = "/wp-content/plugins/wp-file-manager/lib/files/"

# In-process store of uploaded files: { filename: raw bytes }.
STORE = {}


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
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        # Serve back a previously uploaded file (vuln mode only).
        if self.path.startswith(FILES_PREFIX):
            name = self.path[len(FILES_PREFIX):]
            if VULN_MODE and name in STORE:
                self._send(200, STORE[name])
            else:
                self._send(404, "Not Found")
            return
        self._send(200, "<html><body>WordPress</body></html>", "text/html")

    def do_POST(self):
        body = self._read_body()
        if self.path.split("?")[0] == CONNECTOR:
            if not VULN_MODE:
                # Patched plugin restricts access to the connector.
                self._send(403, "Access denied")
                return
            # Parse the multipart upload the way the vulnerable elFinder connector would:
            # extract the uploaded filename and its content, store it, return elFinder JSON.
            fname = None
            content = b""
            m = re.search(rb'filename="([^"]+)"', body)
            if m:
                fname = m.group(1).decode("utf-8", "replace")
                # Content is the bytes after the file part's double CRLF up to the next boundary.
                part = body[m.end():]
                idx = part.find(b"\r\n\r\n")
                if idx != -1:
                    rest = part[idx + 4:]
                    bidx = rest.find(b"\r\n------")
                    content = rest[:bidx] if bidx != -1 else rest
            if fname:
                STORE[fname] = content
                self._send(
                    200,
                    '{"added":[{"name":"%s","hash":"l1_bm9jdGlz","mime":"text/plain",'
                    '"url":"%s%s"}]}' % (fname, FILES_PREFIX, fname),
                    "application/json",
                )
            else:
                self._send(200, '{"error":["errUploadNoFiles"]}', "application/json")
            return
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
