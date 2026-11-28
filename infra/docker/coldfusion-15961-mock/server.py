#!/usr/bin/env python3
# Mock for Adobe ColdFusion CVE-2018-15961 — unauthenticated CKEditor/FCKeditor
# file-manager file upload. PURE STRING SIMULATION: the "vuln" mode stashes the
# uploaded bytes in an in-memory dict and serves them back from /userfiles/file/.
# There is NO subprocess, no os.system/exec, no real webroot write, and no code
# execution of any uploaded content — the upload is treated strictly as inert
# data. The "patched" mode requires authentication and rejects the upload.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("COLDFUSION_MODE", "patched")

UPLOAD_PATH = "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm"

# In-memory store (filename -> inert uploaded bytes). Never written to disk.
STORE = {}

# A fixed marker used only by the "constant" mode — proves that a per-run nonce
# gate is required (this constant will never equal the scanner's random token).
CONSTANT_MARKER = "NOCTIS00000000000000000000000000000000"


def _filename(body):
    m = re.search(rb'filename="([^"]+)"', body)
    return m.group(1).decode("utf-8", "replace") if m else None


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
        path = self.path.split("?", 1)[0]
        if path != UPLOAD_PATH:
            self._send(404, "Not found")
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        if MODE == "patched":
            # Patched: upload requires authentication → reject.
            self._send(403, "Forbidden")
            return

        if MODE == "reflect":
            # Reflect-only: echoes the uploaded content back in the UPLOAD
            # response but never stores/serves it → retrieval finds nothing.
            self._send(200, body.decode("utf-8", "replace"))
            return

        if MODE == "constant":
            # Accepts the upload but serves a constant marker on retrieval
            # regardless of what was uploaded.
            self._send(200, "NOCTIS_COLDFUSION_CONFIRMED uploaded")
            return

        # vuln: stash the inert uploaded bytes keyed by filename.
        fn = _filename(body)
        if fn:
            STORE[fn] = body
        self._send(
            200,
            "NOCTIS_COLDFUSION_CONFIRMED <script>window.parent.OnUploadCompleted(0);</script>",
            ct="text/html",
        )

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if MODE == "constant" and path.startswith("/userfiles/file/"):
            self._send(200, CONSTANT_MARKER)
            return

        if MODE == "vuln" and path.startswith("/userfiles/file/"):
            fn = path.rsplit("/", 1)[-1]
            if fn in STORE:
                self._send(200, STORE[fn])
                return
            self._send(404, "Not found")
            return

        # patched / reflect / unknown paths never serve uploaded content.
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
