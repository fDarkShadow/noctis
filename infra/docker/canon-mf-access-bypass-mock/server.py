#!/usr/bin/env python3
"""Mock Canon MF210/MF220 printer portal — CVE-2018-11711 access bypass.

Faithful two-step flow (OpenVAS gb_canon_printers_access_bypass_vuln.nasl):

  vuln:
    POST /tryLogin.cgi (empty creds "loginM=&0000=0010&0001=&0002=")
      -> 303 See Other, Location: /portal_top.html,
         Set-Cookie: fusion-http-session-id=<sid>   (authenticated session
         granted for empty credentials -> the bypass)
    GET /portal_top.html with Cookie: fusion-http-session-id=<sid>
      -> 200 authenticated admin portal containing all five markers.

  patched:
    POST /tryLogin.cgi
      -> 200 login-error page. It STILL issues a fusion-http-session-id
         cookie (realistic: the login page sets a session), but no 303 and no
         Location -> the bypass does not happen.
    GET /portal_top.html (with or without that cookie)
      -> 200 login page WITHOUT the portal markers: a mere session cookie does
         not unlock the admin portal, so a cookie-only check must NOT fire here.

Env overrides (defaults match the Docker image): CANON_MODE=vuln|patched,
PORT_HTTP (80), PORT_HTTPS (443, 0 disables), CERT_DIR (/certs).
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CANON_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Session id the vulnerable device hands out for empty credentials.
VULN_SID = "A1b2C3d4E5f6A1b2C3d4E5f6"

PORTAL_PAGE = (
    "<html><head><title>Remote UI: Portal</title></head><body>"
    "<div class='header'>"
    "<h1>Device Status</h1>"
    "<a href='/logout.cgi'>Log Out</a>"
    "</div>"
    "<ul>"
    "<li><a href='/addressbook.cgi'>Address Book</a></li>"
    "<li><a href='/cartridge.cgi'>Cartridge Information</a></li>"
    "</ul>"
    "<footer><span>Copyright CANON INC. 2016 All Rights Reserved.</span></footer>"
    "</body></html>"
)

LOGIN_PAGE = (
    "<html><head><title>Remote UI: Login</title></head><body>"
    "<form action='/tryLogin.cgi' method='post'>"
    "<input name='0001' type='password'>"
    "<p>Please log in to access the device.</p>"
    "</form>"
    "<footer>&gt;Copyright CANON INC. 2016 All Rights Reserved.&lt;</footer>"
    "</body></html>"
)

LOGIN_ERROR = (
    "<html><head><title>Remote UI: Login</title></head><body>"
    "<p>The entered department ID or PIN is incorrect.</p>"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
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
        if self.command != "HEAD":
            self.wfile.write(body)

    def _drain_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        if n > 0:
            self.rfile.read(n)

    def do_POST(self):
        self._drain_body()
        if self.path == "/tryLogin.cgi":
            if VULN_MODE:
                # Empty-credential login is accepted: 303 + authenticated session.
                self._send(
                    303,
                    "",
                    extra_headers={
                        "Location": "/portal_top.html",
                        "Set-Cookie": "fusion-http-session-id=%s; path=/" % VULN_SID,
                    },
                )
            else:
                # Login rejected, but a session cookie is still set (realistic).
                self._send(
                    200,
                    LOGIN_ERROR,
                    extra_headers={
                        "Set-Cookie": "fusion-http-session-id=Zz9Yy8Xx7Ww6; path=/",
                    },
                )
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/portal_top.html":
            cookie = self.headers.get("Cookie", "") or ""
            if VULN_MODE and ("fusion-http-session-id=%s" % VULN_SID) in cookie:
                # Valid forged session -> authenticated admin portal.
                self._send(200, PORTAL_PAGE)
            else:
                # No/unknown session (or patched): login page, no portal markers.
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
