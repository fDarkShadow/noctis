#!/usr/bin/env python3
# Mock for CVE-2017-7588 — Brother Devices web authorization bypass.
#
# Both modes serve the SAME Brother web-management fingerprint: the
# /general/status.html login page carries the LogBox password field, a login
# POST returns a Brother-titled page and issues an AuthCookie session cookie,
# and /admin/password.html is the protected administrative password page.
#
# The ONLY difference is the authorization logic:
#   vuln    — a login POST is treated as authenticated regardless of the
#             submitted password (the bug), so the AuthCookie it issues unlocks
#             /admin/password.html. A wrong password therefore grants admin.
#   patched — the device validates the password. A wrong password still yields a
#             (benign, unauthenticated) session cookie — same fingerprint — but
#             /admin/password.html rejects that session (302 back to the login
#             page), so the bypass does not work and no finding is produced.
#
# The admin password field is returned ONLY when the request carries an
# AuthCookie that the server considers authenticated, so the true positive
# proves the wrong-password cookie actually granted access, not that a marker
# is echoed unconditionally.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BROTHER_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# The login password field name advertised by the device (extracted by the
# scanner from  LogBox" name="...").
FIELD_NAME = "B29a01"
# The correct admin password — a real attacker does NOT know it. The scanner
# always submits the wrong value "xyz", so on a patched device the login never
# authenticates.
REAL_PASSWORD = "SuperSecretAdminPass"

# Session cookies the server considers AUTHENTICATED (shared across the HTTP and
# HTTPS listeners in this process).
_authed = set()
_lock = threading.Lock()
_counter = [0]

STATUS_PAGE = (
    "<html><head><title>Brother MFC Web Management</title></head><body>"
    "<h1>Status</h1>"
    "<form method=\"POST\" action=\"/general/status.html\">"
    "<input type=\"password\" id=\"LogBox\" name=\"" + FIELD_NAME + "\">"
    "<input type=\"hidden\" name=\"loginurl\" value=\"/general/status.html\">"
    "</form></body></html>"
)

ADMIN_PAGE = (
    "<html><head><title>Brother MFC Web Management</title></head><body>"
    "<h1>Administrator Password</h1>"
    "<form method=\"POST\" action=\"/admin/password.html\">"
    "<input type=\"password\" class=\"password\" maxlength=\"32\" name=\"B29a02\">"
    "</form></body></html>"
)

LOGIN_PAGE = (
    "<html><head><title>Brother MFC Web Management</title></head><body>"
    "<h1>Login Required</h1>"
    "<form method=\"POST\" action=\"/general/status.html\">"
    "<input type=\"password\" id=\"LogBox\" name=\"" + FIELD_NAME + "\">"
    "</form></body></html>"
)


def _parse_cookie(raw):
    # Extract AuthCookie=<value> from a Cookie: header value.
    if not raw:
        return None
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("AuthCookie="):
            return part[len("AuthCookie="):]
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _issue_cookie(self, authenticated):
        with _lock:
            _counter[0] += 1
            val = "s%06xmfc" % _counter[0]
            if authenticated:
                _authed.add(val)
        return val

    def do_GET(self):
        if self.path == "/general/status.html":
            # Login/status page with the LogBox field (same on both modes).
            self._send(200, STATUS_PAGE)
        elif self.path == "/admin/password.html":
            # Protected admin page: served only for an AUTHENTICATED session.
            cookie = _parse_cookie(self.headers.get("Cookie"))
            if cookie and cookie in _authed:
                self._send(200, ADMIN_PAGE)
            else:
                # Not authenticated → redirect back to the login page.
                self._send(302, LOGIN_PAGE,
                           extra_headers={"Location": "/general/status.html"})
        else:
            self._send(404, "Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("latin-1") if length else ""
        if self.path == "/general/status.html":
            # Parse the submitted password from <field>=<value>.
            submitted = ""
            for pair in body.split("&"):
                if pair.startswith(FIELD_NAME + "="):
                    submitted = pair[len(FIELD_NAME) + 1:]
                    break
            if VULN_MODE:
                # BUG: the session is marked authenticated regardless of the
                # password, so even a wrong password unlocks the admin area.
                cookie = self._issue_cookie(authenticated=True)
            else:
                # Patched: only a correct password authenticates the session.
                # The wrong password "xyz" yields a benign, unauthenticated
                # session cookie (same fingerprint, no privilege).
                cookie = self._issue_cookie(authenticated=(submitted == REAL_PASSWORD))
            self._send(200, STATUS_PAGE,
                       extra_headers={"Set-Cookie": "AuthCookie=%s; path=/" % cookie})
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
