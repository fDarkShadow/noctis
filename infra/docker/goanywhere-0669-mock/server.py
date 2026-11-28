#!/usr/bin/env python3
# Mock for CVE-2023-0669 (Fortra GoAnywhere MFT License Response Servlet pre-auth RCE).
#
# Pure string simulation — NO subprocess, no exec, no file/socket I/O, no real
# deserialization. The mock only decides a status code and echoes back the opaque
# `bundle=` value it received so the feed can prove the servlet is reachable pre-auth.
#
#   vuln mode:    POST /goanywhere/lic/accept  -> 500, reflects the bundle value in a
#                 deserialization-style error body (the fails-open-to-servlet path).
#                 Any other path (incl. the authenticated control path) -> 403, no reflect.
#   patched mode: POST /goanywhere/lic/accept  -> 404 (endpoint removed/hardened), no reflect.
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("GOANYWHERE_MODE", "patched") == "vuln"

LICENSE_SERVLET = "/goanywhere/lic/accept"


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

    def _bundle_value(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        params = urllib.parse.parse_qs(raw, keep_blank_values=True)
        vals = params.get("bundle", [])
        return vals[0] if vals else ""

    def do_POST(self):
        bundle = self._bundle_value()
        path = self.path.split("?", 1)[0]
        if VULN_MODE and path == LICENSE_SERVLET:
            # Vulnerable: request reaches the License Response Servlet without auth,
            # deserialization fails on the opaque token, and the servlet reflects it.
            body = (
                "<html><body>"
                "NOCTIS_GOANYWHERE_CONFIRMED"
                "<pre>java.io.IOException: com.linoma.dpa.security.SecurityException: "
                "Unable to decrypt license response bundle: "
                + bundle
                + "\n\tat com.linoma.ga.ui.admin.servlet.LicenseResponseServlet.doPost"
                "</pre></body></html>"
            )
            self._send(500, body)
        else:
            # Patched endpoint, or any non-servlet / authenticated path: never reflect.
            self._send(403 if path.startswith("/goanywhere/auth/") else 404,
                       "<html><body>Access denied</body></html>")

    def do_GET(self):
        self._send(404, "<html><body>404 Not Found</body></html>")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
