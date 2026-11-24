#!/usr/bin/env python3
# Mock for CVE-2018-11692 — Canon Printers Authentication Bypass.
#
# Both modes serve the same Canon Remote UI fingerprint: a home page, a login
# endpoint /tlogin.cgi that issues a CookieID session cookie, and the device
# frame endpoint /frame.cgi?page=DevInfoSetDev. The modes differ ONLY in whether
# the Administrator Mode password is enforced.
#
# Vuln mode: /tlogin.cgi with Action=LOGIN and an empty user_name grants an
#   ADMIN session cookie (CookieID=admin...). Presenting that cookie to
#   /frame.cgi?page=DevInfoSetDev returns the management frameset containing the
#   marker switch("DevInfoSetDev") — the real exploit signal.
# Patched mode: /tlogin.cgi still issues a CookieID session cookie (same product
#   fingerprint) but it is an UNAUTHENTICATED guest session; /frame.cgi always
#   returns the login page, never the switch("DevInfoSetDev") marker. So the bare
#   cookie is still present but the auth bypass does not work → zero findings.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CANON_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

ADMIN_COOKIE = "admin1610705327"   # issued only by the vulnerable login
GUEST_COOKIE = "guest00000000"     # issued by the patched (auth-enforcing) login

HOME_PAGE = (
    "<html><head><title>Canon LBP6650 Remote UI</title></head>"
    "<body><h1>Canon Remote UI</h1><p>Copyright CANON INC.</p>"
    "<a href=\"/tlogin.cgi\">Administrator Mode</a></body></html>"
)

LOGIN_PAGE = (
    "<html><head><title>Canon Login</title></head>"
    "<body><form action=\"/tlogin.cgi\" method=\"post\">"
    "<input name=\"user_name\"><input type=\"submit\" value=\"Log In\"></form>"
    "<p>Copyright CANON INC.</p></body></html>"
)

# Authenticated device-management frameset. The script marker switch("DevInfoSetDev")
# is what the NASL / feed confirms on.
DEVINFO_PAGE = (
    "<html><head><title>DevInfoSetDev</title>"
    "<script>function init(){switch(\"DevInfoSetDev\"){case 0:break;}}</script>"
    "</head><body><h2>Device Information Settings</h2>"
    "<p>Model: Canon LBP6650  Copyright CANON INC.</p></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n).decode("latin-1") if n else ""

    def do_POST(self):
        if self.path == "/tlogin.cgi":
            data = self._body()
            # The auth bypass requires the real login form (login_mode=user), so
            # the payload genuinely matters — a bare POST does not grant a session.
            if VULN_MODE and "Action=LOGIN" in data and "login_mode=user" in data:
                # Auth bypass: admin session granted without a password.
                self._send(200, LOGIN_PAGE,
                           extra_headers={"Set-Cookie": "CookieID=%s; path=/" % ADMIN_COOKIE})
            else:
                # Patched (or non-LOGIN): a session cookie is still issued, but it
                # is an unauthenticated guest session.
                self._send(200, LOGIN_PAGE,
                           extra_headers={"Set-Cookie": "CookieID=%s; path=/" % GUEST_COOKIE})
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/frame.cgi?page=DevInfoSetDev":
            cookie = self.headers.get("Cookie", "")
            # The management frame is only served to an administrative session,
            # which the NASL marks with "Login=11" alongside the bypass CookieID.
            if (VULN_MODE and ("CookieID=" + ADMIN_COOKIE) in cookie
                    and "Login=11" in cookie):
                # Bypass cookie accepted → serve the management frameset.
                self._send(200, DEVINFO_PAGE)
            else:
                # No valid admin session → bounce back to the login page (no marker).
                self._send(200, LOGIN_PAGE)
        elif self.path in ("/", "/index.html"):
            self._send(200, HOME_PAGE)
        else:
            self._send(404, "Not found")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
