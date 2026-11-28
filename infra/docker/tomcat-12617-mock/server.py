#!/usr/bin/env python3
"""Mock for CVE-2017-12617 (Apache Tomcat JSP upload via PUT, readonly=false).

Detection is a genuine write-then-read differential: the feed PUTs a benign,
inert .jsp file (via the trailing-slash bypass `/<name>.jsp/`) whose body it
alone chose, then GETs it back and checks that ITS OWN unique content is
served. This mock never fabricates the detection marker — it stores exactly
the bytes it was given and echoes them back, so the feed only ever matches on
content it wrote.

  vuln mode    : DefaultServlet is writable (readonly=false). A PUT to a
                 `*.jsp/` path is accepted (201 Created) and the body is
                 stored under the de-slashed path; a later GET returns it.
  patched mode : PUT is rejected (403 Forbidden) and nothing is stored, so a
                 subsequent GET of the probe path is 404 Not Found.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("TOMCAT_MODE", "patched") == "vuln"

# In-memory "webroot": path -> stored body. Only written in vuln mode.
STORE = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Apache-Coyote/1.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_PUT(self):
        body = self._read_body()
        # The real bug: DefaultServlet writable + the JspServlet-mapping bypass
        # of a trailing "/" lets an unauthenticated PUT write a .jsp file.
        if VULN_MODE and self.path.endswith(".jsp/"):
            # File lands at the de-slashed path, exactly as Tomcat writes it.
            stored_path = self.path[:-1]
            STORE[stored_path] = body
            self._send(201, b"")
        else:
            # Patched Tomcat refuses the write.
            self._send(403, "Forbidden")

    def do_GET(self):
        if self.path in STORE:
            # Serve back exactly what was uploaded (inert bytes, verbatim).
            self._send(200, STORE[self.path], "application/octet-stream")
        elif self.path in ("/", "/index.html"):
            self._send(200, b"<html><body><h1>Apache Tomcat</h1></body></html>", "text/html")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        self._read_body()
        self._send(405, "Method Not Allowed")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
