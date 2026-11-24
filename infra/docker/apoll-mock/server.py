#!/usr/bin/env python3
"""Mock for Dragan Mitic Apoll admin/login.php SQL injection (CVE-2008-6270 /
CVE-2008-6272).

Both modes serve the product realistically: GET /admin/login.php returns a 200
Apoll admin login page (same fingerprint, no redirect), which the NASL gate
requires. The modes differ only on how the login POST is handled:

* vuln mode: when the POST body carries the real SQL-injection tautology in the
  ``username`` field (``' or ' 1=1'-- '`` — the NASL payload), the login query
  evaluates true, the attacker is authenticated and the server redirects to the
  admin index with ``Location: index.php``. A normal/failed login (no injection)
  just re-serves the login page (200, no redirect) — so the redirect proves the
  payload mattered, not that the mock echoes a marker unconditionally.

* patched mode: the credentials are treated as data (parameterised/escaped), so
  the injection does NOT authenticate. Every login attempt — injection or not —
  is rejected with the login page re-shown (200, "Invalid credentials", no
  redirect). The product is fully served; only the vulnerable behaviour is gone,
  so the detection pattern ("Location: index.php") is absent -> zero findings.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("APOLL_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

LOGIN_PAGE = (
    "<!DOCTYPE html><html><head><title>Apoll :: Administration</title></head>"
    "<body><h1>Apoll Admin Login</h1>"
    "<form name=\"login\" action=\"login.php\" method=\"post\">"
    "<input type=\"text\" name=\"username\">"
    "<input type=\"password\" name=\"password\">"
    "<input type=\"submit\" name=\"submit\" value=\"Login\"></form>"
    "<p>Powered by Apoll</p></body></html>"
)
LOGIN_PAGE_ERR = LOGIN_PAGE.replace(
    "<h1>Apoll Admin Login</h1>",
    "<h1>Apoll Admin Login</h1><p class=\"error\">Invalid username or password.</p>",
)

# The exact SQL-injection tautology the NASL submits in the username field.
INJECTION = "' or ' 1=1'-- '"


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

    def do_GET(self):
        # The login page is always present (both modes) — the NASL gate needs a
        # 200 with no pre-existing redirect.
        if self.path.split("?", 1)[0] == "/admin/login.php":
            self._send(200, LOGIN_PAGE)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/admin/login.php":
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("latin-1") if length else ""
        is_injection = "username=" in body and INJECTION in body
        if VULN_MODE and is_injection:
            # Injected tautology authenticates -> redirect to the admin index.
            self._send(302, "", extra_headers={"Location": "index.php"})
        else:
            # Patched (always) or a non-injection login in vuln mode: rejected,
            # login page re-served with an error. No redirect.
            self._send(200, LOGIN_PAGE_ERR)


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
