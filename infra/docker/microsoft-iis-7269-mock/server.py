#!/usr/bin/env python3
"""Pure string-simulation mock for CVE-2017-7269 (IIS 6.0 WebDAV).

Vuln mode:    Server: Microsoft-IIS/6.0, WebDAV ENABLED
              -> PROPFIND returns 207 Multi-Status with a DAV multistatus body.
Patched mode: Server: Microsoft-IIS/6.0, WebDAV DISABLED
              -> PROPFIND returns 403 Forbidden (no multistatus body).

No subprocess / exec / file I/O — this is a safe fingerprint target only.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("IIS_MODE", "patched") == "vuln"

MULTISTATUS = (
    '<?xml version="1.0"?>\r\n'
    '<a:multistatus xmlns:a="DAV:">\r\n'
    '  <a:response>\r\n'
    '    <a:href>http://localhost/</a:href>\r\n'
    '    <a:propstat>\r\n'
    '      <a:status>HTTP/1.1 200 OK</a:status>\r\n'
    '    </a:propstat>\r\n'
    '  </a:response>\r\n'
    '</a:multistatus>\r\n'
)


class Handler(BaseHTTPRequestHandler):
    # Emit the real IIS 6.0 Server banner (signal A) in both modes.
    server_version = "Microsoft-IIS/6.0"
    sys_version = ""

    def version_string(self):
        return "Microsoft-IIS/6.0"

    def log_message(self, *args):
        pass

    def _send(self, code, phrase, body="", ct="text/plain", extra=None):
        if isinstance(body, str):
            body = body.encode()
        # send_response writes the status line + Server + Date headers.
        self.send_response(code, phrase)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        # Control request: always 200, never 207. WebDAV servers advertise
        # the DAV header + PROPFIND in Allow; it is never a Multi-Status.
        self._send(
            200, "OK", "",
            extra={
                "Allow": "OPTIONS, GET, HEAD, POST, PROPFIND",
                "DAV": "1, 2" if VULN_MODE else "",
                "Public": "OPTIONS, GET, HEAD, POST",
            },
        )

    def do_PROPFIND(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        if VULN_MODE:
            self._send(207, "Multi-Status", MULTISTATUS, ct="text/xml")
        else:
            # WebDAV disabled on the patched host.
            self._send(403, "Forbidden", "WebDAV is disabled")

    def do_GET(self):
        self._send(200, "OK", "<html><body>IIS</body></html>", ct="text/html")

    def do_HEAD(self):
        self._send(200, "OK", "")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)  # HTTP:80 + HTTPS:443 (cert from the base image)
