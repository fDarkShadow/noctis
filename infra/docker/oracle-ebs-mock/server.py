#!/usr/bin/env python3
"""Mock for Oracle E-Business Suite IESFOOTPRINT SQL injection (CVE-2017-3549).

Both modes serve the /OA_HTML/AppsLocalLogin.jsp login page used by the
preliminary gate. The login response carries the two Set-Cookie headers a real
EBS hands out — the JSESSIONID session cookie and a second, non-J cookie — which
the feed harvests and must replay on the exploit request.

vuln   : /OA_HTML/iesfootprint.jsp, *when the harvested session cookie is sent*,
         returns HTTP 200 and reflects the injected request parameters into an
         authenticated-looking Oracle Applications page (SQLi marker + session
         chrome present). Without the session cookie it bounces to login — so the
         TP genuinely exercises the cookie-harvest step.
patched: iesfootprint.jsp still serves HTTP 200 (the endpoint exists on a patched
         EBS) but the injected value is validated away — no reflected marker, so
         the scan reports nothing.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ORACLE_EBS_MODE", "patched") == "vuln"

# Login page: carries BOTH gate markers ("title>Login</title" and
# content="Oracle UIX") that the feed AND-checks before proceeding.
LOGIN_PAGE = (
    "<html><head><title>Login</title>"
    '<meta name="generator" content="Oracle UIX"></head>'
    "<body>Oracle E-Business Suite Login</body></html>"
)

# Vulnerable iesfootprint reflection: injected marker reflected verbatim plus the
# Oracle Applications session chrome the feed's extra-check requires.
VULN_PAGE = (
    "<html><head><title>Oracle Applications</title></head><body>"
    '<a href="/OA_HTML/OALogout.jsp">Sign Out</a>'
    "<h1>Oracle Applications</h1>"
    "<div>dscriptId=<>SQL Injection Test</div>"
    "</body></html>"
)

# Patched iesfootprint: endpoint exists and returns 200, but the attacker value
# is not reflected (validated/stripped) — no SQLi marker, no chrome.
PATCHED_PAGE = (
    "<html><head><title>Footprint</title></head><body>"
    "<div>Report parameters accepted.</div>"
    "</body></html>"
)

# Second, non-J session cookie served alongside JSESSIONID (matches the NASL's
# `Set-Cookie: ([^J;]+)` harvest of the first non-J cookie).
SESSION_COOKIES = [
    "JSESSIONID=0000noctismockSESSION; path=/; HttpOnly",
    "oracle.uix=0; path=/",
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", cookies=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path preserves the %3C%3E encoding of the raw tcp_connect request.
        path = self.path
        if path.startswith("/OA_HTML/AppsLocalLogin.jsp"):
            # Hand out the session cookies on the login page, like a real EBS.
            self._send(200, LOGIN_PAGE, cookies=SESSION_COOKIES)
            return
        if path.startswith("/OA_HTML/iesfootprint.jsp"):
            if VULN_MODE:
                cookie_hdr = self.headers.get("Cookie", "")
                if "JSESSIONID" in cookie_hdr:
                    self._send(200, VULN_PAGE)
                else:
                    # No live session → EBS bounces the request back to login.
                    self._send(200, LOGIN_PAGE, cookies=SESSION_COOKIES)
            else:
                # Patched: endpoint present, 200, but no unvalidated reflection.
                self._send(200, PATCHED_PAGE)
            return
        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
