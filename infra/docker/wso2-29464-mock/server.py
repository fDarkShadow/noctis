#!/usr/bin/env python3
# Mock for WSO2 Carbon unauthenticated arbitrary file upload (CVE-2022-29464).
#
# Pure string-simulation of the unauth upload+retrieve primitive — NO
# subprocess / os.system / exec, NO real file written to a webroot, NO
# webshell. The "uploaded" bytes are kept in an in-memory dict and served
# back verbatim, which is all the inert noctis detection probe needs.
#
#   vuln     : /fileupload/toolsAny stores the uploaded part (keyed by the
#              basename taken from the traversal `name` field); the file is
#              then readable at /authenticationendpoint/<basename>.
#   patched  : /fileupload/toolsAny requires authentication (403) and stores
#              nothing, so the retrieval path always 404s.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("WSO2_MODE", "patched") == "vuln"

# Web-reachable directory the traversal is expected to drop files into, and
# the prefix it is served back under.
WEBAPP_MARKER = "repository/deployment/server/webapps/authenticationendpoint/"
SERVE_PREFIX = "/authenticationendpoint/"

# In-memory store simulating files that landed in the webapp directory.
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

    def do_GET(self):
        if self.path.startswith(SERVE_PREFIX):
            base = self.path[len(SERVE_PREFIX):].split("?", 1)[0]
            if base in STORE:
                # Serve the inert text that was "uploaded" earlier.
                self._send(200, STORE[base])
                return
            self._send(404, "Not found")
            return
        if self.path == "/" or self.path == "/carbon/":
            self._send(200, "WSO2 Carbon Management Console")
            return
        self._send(404, "Not found")

    def do_POST(self):
        if self.path.startswith("/fileupload"):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")

            if not VULN_MODE:
                # Patched: the fileupload endpoint requires authentication and
                # rejects the unauthenticated multipart write outright.
                self._send(403, "Forbidden")
                return

            # Vulnerable: parse the multipart part, honour the traversal in the
            # `name` field, and stash the inert content keyed by basename.
            m_name = re.search(r'name="([^"]+)"', raw)
            if not m_name or WEBAPP_MARKER not in m_name.group(1):
                self._send(400, "Bad upload")
                return
            base = m_name.group(1).rsplit("/", 1)[-1]

            # Content = bytes between the part header block and the closing
            # boundary. Tolerant of LF or CRLF line endings.
            split = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
            content = split[1] if len(split) > 1 else ""
            content = re.sub(r"\r?\n--[^\r\n]*--\s*$", "", content)

            STORE[base] = content
            self._send(200, "NOCTIS_WSO2_CONFIRMED upload stored")
            return
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
