#!/usr/bin/env python3
"""Mock for Canon LBP6030w authentication bypass (CVE-2018-12049).

Faithful to OpenVAS/Greenbone NASL
2018/canon/gb_canon_printer_lbp6030w_auth_bypass_vuln.nasl (GPL-2.0-only):

  1. POST /checkLogin.cgi  body: iToken=&i0012=1&i0016=   (empty administrator PIN)
  2. The device answers Set-Cookie: sessid=<id>
  3. GET /portal_top.html with that cookie renders the *System Manager* portal

Vuln mode: /checkLogin.cgi accepts the empty PIN and hands back a valid sessid;
GET /portal_top.html with that sessid renders the authenticated System Manager
portal (userName">System&nbsp;Manager, >Log Out<, Copyright CANON INC,
<title>Remote UI: Portal: LBP6030w ...).

Patched mode: /checkLogin.cgi rejects the empty PIN (re-serves the login page,
no sessid), so no authenticated session is ever issued. Both modes serve the
same product fingerprint and the same /portal_top.html endpoint; the portal is
rendered only for a request that already carries the valid authenticated sessid,
so a non-vulnerable instance never exposes the System Manager markers.
"""
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CANON_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# The authenticated session id the vulnerable device hands out for the empty PIN.
VALID_SESSID = "8f14e45fceea167a5a36dedd4bea2543"

LOGIN_PAGE = (
    "<html><head>"
    "<title>Remote UI: Login: LBP6030w / LBP6030</title>"
    "</head><body>"
    "<div id=\"pageHeader\">Canon</div>"
    "<form action=\"/checkLogin.cgi\" method=\"post\">"
    "<input type=\"hidden\" name=\"iToken\" value=\"\">"
    "<input type=\"password\" name=\"i0016\">"
    "<input type=\"submit\" value=\"Log In\">"
    "</form>"
    "<div id=\"footer\"><span>Copyright CANON INC. 2015 All Rights Reserved</span></div>"
    "</body></html>"
)

PORTAL_PAGE = (
    "<html><head>"
    "<title>Remote UI: Portal: LBP6030w / LBP6030</title>"
    "</head><body>"
    "<div id=\"deviceName\">LBP6030w / LBP6030</div>"
    "<table><tr><td id=\"userName\">System&nbsp;Manager</td></tr></table>"
    "<div id=\"nav\"><a href=\"/portal_top.html\">Portal</a>"
    "<a href=\"/logout.cgi\">Log Out</a></div>"
    "<div id=\"footer\"><span>Copyright CANON INC. 2015 All Rights Reserved</span></div>"
    "</body></html>"
)


def _has_empty_pin(body):
    """The payload: iToken present and the PIN field i0016 left empty."""
    if "iToken=" not in body:
        return False
    return re.search(r"(^|&)i0016=(&|$)", body) is not None


def _has_valid_sessid(cookie_header):
    if not cookie_header:
        return False
    return re.search(r"(^|[;\s])sessid=" + VALID_SESSID + r"(?:[;\s]|$)", cookie_header) is not None


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

    def do_POST(self):
        if self.path == "/checkLogin.cgi":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("latin-1") if length else ""
            if VULN_MODE and _has_empty_pin(body):
                # Vulnerable: empty administrator PIN is accepted → session granted.
                self._send(
                    200,
                    "<html><head><title>Remote UI: Portal: LBP6030w</title></head>"
                    "<body>Login OK</body></html>",
                    extra_headers={"Set-Cookie": "sessid=%s; path=/" % VALID_SESSID},
                )
            else:
                # Patched (or a non-empty/incorrect PIN): authentication fails,
                # the login page is re-served and no session cookie is issued.
                self._send(200, LOGIN_PAGE)
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/portal_top.html" or self.path.startswith("/portal_top.html?"):
            if _has_valid_sessid(self.headers.get("Cookie", "")):
                self._send(200, PORTAL_PAGE)
            else:
                # Unauthenticated: the device shows its login page.
                self._send(200, LOGIN_PAGE)
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
