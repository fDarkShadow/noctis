#!/usr/bin/env python3
"""ForgeRock OpenAM mock — CVE-2021-35464.

Vuln mode exposes the Jato `ccversion` Masthead.jsp "Version Information" page
unauthenticated via the Tomcat `..;/` path-parameter bypass (reachable at
`/openam/oauth2/..;/ccversion/Masthead.jsp`), returning HTTP 200 with a
JSESSIONID session cookie and the real OpenAM version page markers.
Patched mode removes/protects the endpoint and returns 404.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("OPENAM_MODE", "patched") == "vuln"

# Genuine OpenAM ccversion Masthead.jsp markers (Nuclei/Metasploit rely on
# "Version Information -" and the self-referencing "openam/ccversion/Masthead.jsp").
MASTHEAD = (
    "<!-- NOCTIS_FORGEROCK_OPENAM_CONFIRMED -->\n"
    "<html>\n<head><title>Version Information</title></head>\n"
    "<body>\n"
    "<form name=\"Masthead\" method=\"post\" "
    "action=\"../console/openam/ccversion/Masthead.jsp\">\n"
    "<h1>Version Information -</h1>\n"
    "<table><tr><td>Version:</td><td>OpenAM 13.5.2 Build 2017-June-13</td></tr>\n"
    "<tr><td>Revision:</td><td>d1cd597</td></tr></table>\n"
    "</form>\n"
    "</body>\n</html>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html;charset=UTF-8", cookie=False):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", "JSESSIONID=A1B2C3D4E5F6; Path=/openam; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # The `..;/` request-target reaches ccversion only when the auth
        # filter is bypassable (vulnerable deployment).
        is_ccversion = "ccversion/Masthead.jsp" in self.path and "..;/" in self.path
        if VULN_MODE and is_ccversion:
            self._send(200, MASTHEAD, cookie=True)
        elif is_ccversion:
            # Patched: the bypass no longer reaches the protected endpoint.
            self._send(404, "Not Found")
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
