#!/usr/bin/env python3
"""Mock PaperCut MF/NG — CVE-2023-27350 SetupCompleted auth bypass.

Vuln mode: GET /app?service=page/SetupCompleted with no session cookie reaches
the authenticated Setup-Completed admin page (200 + admin-page markers).
Patched mode: the same unauthenticated request is redirected (302) to the
admin login page, so the admin page is never served.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PAPERCUT_MODE", "patched") == "vuln"

VERSION = "22.0.5" if VULN_MODE else "22.0.9"

# The authenticated Setup-Completed admin page a vulnerable server serves to an
# unauthenticated client. Contains the admin-page markers a real page carries.
SETUP_COMPLETED_PAGE = (
    "<!DOCTYPE html><html><head><title>PaperCut MF : Configuration Wizard</title>"
    "<meta name=\"csrf\" content=\"a1b2c3\"></head>"
    "<body class=\"admin-main\">"
    "<h1>Configuration Wizard</h1>"
    "<p>Setup Complete. Your PaperCut MF system is ready to use.</p>"
    "<a href=\"/app?service=page/Dashboard\">Go to the admin interface</a>"
    "</body></html>"
)

# The admin login form a patched server renders instead.
LOGIN_PAGE = (
    "<!DOCTYPE html><html><head><title>PaperCut MF : Login</title></head>"
    "<body><form name=\"loginForm\" action=\"/app?service=page/Login\">"
    "<input name=\"j_username\"><input name=\"j_password\" type=\"password\">"
    "</form></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "PaperCut")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        query = self.path[len(path):]

        # SetupCompleted admin page — the auth-bypass surface.
        if path == "/app" and "service=page/SetupCompleted" in query:
            if VULN_MODE:
                # Reachable without a session cookie → admin page served.
                self._send(200, SETUP_COMPLETED_PAGE, "text/html")
            else:
                # Patched: unauthenticated request bounced to the login page.
                self._send(
                    302,
                    "",
                    "text/html",
                    extra_headers={"Location": "/app?service=page/Login"},
                )
            return

        # Fingerprint endpoint — dashboard landing (both modes).
        if path == "/app":
            self._send(200, f"PaperCut MF {VERSION} - Dashboard", "text/html")
            return

        self._send(404, "Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
