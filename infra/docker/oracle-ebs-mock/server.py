#!/usr/bin/env python3
"""Mock for Oracle E-Business Suite IESFOOTPRINT SQL injection (CVE-2017-3549).

The request flow mirrors the source NASL:

  * /OA_HTML/AppsLocalLogin.jsp (both modes) answers with a 302 whose
    ``Location:`` points at a ``/OA_HTML/RF.jsp`` target and whose body ends
    ``</A></BODY></HTML>`` — the redirect the NASL extracts and follows. No
    session cookie or login marker is served here, so the feed MUST follow the
    redirect to proceed (proving the redirect hop, not a shortcut on the first
    reply).
  * /OA_HTML/RF.jsp (both modes) is the redirect target: it serves the login
    page carrying BOTH gate markers ("title>Login</title" and
    content="Oracle UIX") and the two Set-Cookie headers a real EBS hands out
    (JSESSIONID + a second, non-J cookie) that the feed harvests and replays.
  * /OA_HTML/iesfootprint.jsp:
      vuln   : returns HTTP 200 and reflects the injected parameters into an
               authenticated Oracle Applications page (SQLi marker + session
               chrome) ONLY when BOTH harvested cookies (JSESSIONID and the
               second oracle.uix cookie) are replayed — so the TP genuinely
               exercises the two-cookie harvest. Otherwise it bounces to login.
      patched: returns HTTP 200 (the endpoint exists on a patched EBS) but the
               injected value is validated away — no reflected marker, so the
               scan reports nothing.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ORACLE_EBS_MODE", "patched") == "vuln"

# AppsLocalLogin.jsp redirect target (the /OA path the NASL follows).
REDIRECT_PATH = "/OA_HTML/RF.jsp?function_id=1019663&resp_appl_id=-1"

# Body of the AppsLocalLogin.jsp redirect reply — ends with the exact
# </A></BODY></HTML> tail the NASL's Location pattern anchors on.
REDIRECT_BODY = (
    "<HTML><BODY>Object moved to "
    '<A HREF="' + REDIRECT_PATH + '">here</A></BODY></HTML>'
)

# Login page served on the redirect target: carries BOTH gate markers
# ("title>Login</title" and content="Oracle UIX") that the feed AND-checks.
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

# JSESSIONID plus a second, non-J session cookie. The feed harvests cookie1 via
# `Set-Cookie: (JSESSIONID[^;]+)` and cookie2 via `Set-Cookie: ([^J;]+)` (the
# first non-J Set-Cookie), then replays both.
SESSION_COOKIES = [
    "JSESSIONID=0000noctismockSESSION; path=/; HttpOnly",
    "oracle.uix=0; path=/",
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", cookies=None, location=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if location is not None:
            self.send_header("Location", location)
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path preserves the %3C%3E encoding of the raw tcp_connect request.
        path = self.path
        if path.startswith("/OA_HTML/AppsLocalLogin.jsp"):
            # Redirect to the /OA target — no cookies / markers here, forcing
            # the feed to follow the redirect like a real EBS.
            self._send(302, REDIRECT_BODY, location=REDIRECT_PATH)
            return
        if path.startswith("/OA_HTML/RF.jsp"):
            # Redirect target: the login page + session cookies.
            self._send(200, LOGIN_PAGE, cookies=SESSION_COOKIES)
            return
        if path.startswith("/OA_HTML/iesfootprint.jsp"):
            if VULN_MODE:
                cookie_hdr = self.headers.get("Cookie", "")
                # Require BOTH harvested cookies, proving the two-cookie harvest.
                if "JSESSIONID" in cookie_hdr and "oracle.uix" in cookie_hdr:
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
