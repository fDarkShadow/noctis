#!/usr/bin/env python3
"""Mock for Apache Axis2 admin console (CVE-2010-0219 — default credentials).

Four AXIS2_MODE values model the two real Axis2 login response shapes, each in
a vulnerable and a non-vulnerable (patched) form:

  vuln             Axis2 <= 1.7.2 with default creds: POST /axis2-admin/login
                   with admin/axis2 returns 200 directly with the admin module
                   page ("Welcome to Axis2 Web Admin Module !!") and a JSESSIONID.
  vuln_redirect    Axis2 >= 1.7.3 with default creds: the POST returns a 302 to
                   /axis2-admin/ with a JSESSIONID; GET /axis2-admin/ carrying
                   that exact cookie returns the admin module page. The welcome
                   text is therefore NOT in the POST response — the scanner must
                   follow the redirect with the issued cookie, as the NASL does.
  patched          default creds rejected: the login page is re-rendered with
                   "Invalid auth credentials!" (200), but a JSESSIONID cookie is
                   STILL issued (as a real servlet container does). TN proves the
                   feed keys on the authenticated page body, not on the cookie.
  patched_redirect default creds rejected on a modern release: the POST 302s back
                   to /axis2-admin/login (with a JSESSIONID); following it returns
                   the login page with no welcome text. TN proves the feed does
                   not fire merely because a login POST redirected + set a cookie.
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

AXIS2_MODE = os.environ.get("AXIS2_MODE", "patched")
VULN_MODE = AXIS2_MODE.startswith("vuln")
REDIRECT_MODE = AXIS2_MODE.endswith("redirect")
# The session id the vuln redirect flow issues and then requires on the follow-up
# GET — proves the scanner extracted and forwarded the JSESSIONID cookie.
VULN_SESSION = "VULNREDIRECTSESSION0123456789AB"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

LOGIN_PAGE = (
    "<html><head><title>Axis2 :: Administration</title></head>"
    "<body><form method=\"post\" action=\"login\">"
    "<input name=\"userName\"><input name=\"password\" type=\"password\">"
    "<input type=\"submit\" name=\"submit\"></form></body></html>"
)
ADMIN_PAGE = (
    "<html><head><title>Axis2 :: Administration Page</title></head>"
    "<body><h1>Welcome to Axis2 Web Admin Module !!</h1>"
    "<a href=\"upload\">Upload Service</a></body></html>"
)


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            return self.rfile.read(length).decode("latin-1")
        return ""

    def _cookie_value(self, name):
        cookie = self.headers.get("Cookie", "") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return ""

    def do_POST(self):
        if self.path == "/axis2-admin/login":
            body = self._read_body()
            default_creds = "userName=admin" in body and "password=axis2" in body
            if VULN_MODE and default_creds and not REDIRECT_MODE:
                # Axis2 <= 1.7.2: successful login → admin module page directly
                # (and a session cookie).
                self._send(
                    200,
                    ADMIN_PAGE,
                    extra_headers={"Set-Cookie": "JSESSIONID=A1B2C3D4E5F6A7B8C9D0E1F2; Path=/axis2"},
                )
            elif VULN_MODE and default_creds and REDIRECT_MODE:
                # Axis2 >= 1.7.3: successful login → 302 to the admin area with a
                # JSESSIONID; the welcome text is NOT here. The scanner must GET
                # the Location carrying this cookie.
                self._send(
                    302,
                    "",
                    extra_headers={
                        "Location": "/axis2-admin/",
                        "Set-Cookie": "JSESSIONID=%s; Path=/axis2" % VULN_SESSION,
                    },
                )
            elif REDIRECT_MODE:
                # Modern release, default creds rejected: 302 back to the login
                # page (with a cookie). Following it yields no welcome text.
                self._send(
                    302,
                    "",
                    extra_headers={
                        "Location": "/axis2-admin/login",
                        "Set-Cookie": "JSESSIONID=F2E1D0C9B8A7F6E5D4C3B2A1; Path=/axis2",
                    },
                )
            else:
                # <= 1.7.2 release, default creds rejected: the login page is
                # re-rendered with an error, but a JSESSIONID cookie is STILL
                # issued (as a real servlet container does). The feed must not
                # fire on this.
                self._send(
                    200,
                    LOGIN_PAGE.replace("<body>", "<body><p>Invalid auth credentials!</p>"),
                    extra_headers={"Set-Cookie": "JSESSIONID=F2E1D0C9B8A7F6E5D4C3B2A1; Path=/axis2"},
                )
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path == "/axis2-admin/":
            # Authenticated admin area reached only via the post-login redirect.
            # Vuln redirect mode serves the admin module page, but only when the
            # request carries the JSESSIONID issued by the successful login —
            # proving the scanner extracted and forwarded the cookie.
            if VULN_MODE and REDIRECT_MODE and self._cookie_value("JSESSIONID") == VULN_SESSION:
                self._send(200, ADMIN_PAGE)
            else:
                self._send(200, LOGIN_PAGE)
        elif self.path == "/axis2-admin/login":
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
