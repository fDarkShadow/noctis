#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve   # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("VCENTER_MODE", "patched") == "vuln"

# The vSphere Client vRealize Operations plugin upload servlet.
UPLOADOVA = "/ui/vropspluginui/rest/services/uploadova"

VSPHERE_LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>vSphere - Client</title></head>
<body><div id="login"><h1>VMware vSphere</h1></div></body>
</html>"""

# Genuine Apache Tomcat / servlet 405 body — what a vulnerable vCenter returns once the
# unauthenticated request actually reaches the upload servlet. Not a noctis marker.
SERVLET_405 = (
    "<html><head><title>Apache Tomcat - Error report</title></head>"
    "<body><h1>HTTP Status 405 - HTTP method GET is not supported by this URL</h1>"
    "<p><b>message</b> <u>HTTP method GET is not supported by this URL</u></p>"
    "</body></html>"
)


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
        if self.path == UPLOADOVA:
            if VULN_MODE:
                # Servlet reachable pre-auth: rejects GET with its own 405.
                self._send(405, SERVLET_405)
            else:
                # Patched: request rejected before the servlet (auth required).
                self._send(401, "<html><body>401 Unauthorized</body></html>")
        elif self.path == "/" or self.path.startswith("/ui"):
            self._send(200, VSPHERE_LOGIN_PAGE)
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
