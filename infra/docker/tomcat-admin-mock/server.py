#!/usr/bin/env python3
# Mock for CVE-2009-3099 — Apache Tomcat Server Administration default/hardcoded
# credentials. Models the real NASL form-auth flow
# (2015/apache/sw_tomcat_admin_default_credentials.nasl):
#
#   GET  /admin/                               -> login page + JSESSIONID cookie
#   POST /admin/j_security_check;jsessionid=.. -> form-auth login
#   GET  /admin/banner.jsp                      -> authenticated admin UI
#
# Both modes serve the product realistically: same endpoints, same
# "Tomcat Web Server Administration Tool" fingerprint, same JSESSIONID cookie,
# and a 302 redirect from j_security_check. The ONLY difference:
#   vuln    — accepts the default credential admin:admin, authenticates the
#             session, redirects to /admin/mainFrame.jsp, and then serves the
#             authenticated /admin/banner.jsp (the real exploit signal).
#   patched — rejects every credential (default creds no longer valid),
#             redirects the login to /admin/error.jsp, and never authenticates
#             a session, so /admin/banner.jsp stays on the login page.
#
# The authenticated banner is served ONLY for a JSESSIONID that was actually
# authenticated by submitting the default credential — the payload must matter.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VULN_MODE = os.environ.get("TOMCAT_ADMIN_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

# Fixed session id the admin app hands out (mirrors a Tomcat JSESSIONID).
SESSION_ID = "A1B2C3D4E5F6A7B8C9D0E1F2"

# Default/known credentials shipped with the Tomcat admin webapp (the set the
# CVE chain is about). A login succeeds only when one of these is submitted.
DEFAULT_CREDS = {
    ("admin", "admin"),
    ("admin", ""),
    ("tomcat", "tomcat"),
    ("ovwebusr", "OvW*busr1"),
    ("j2deployer", "j2deployer"),
    ("cxsdk", "kdsxc"),
    ("ADMIN", "ADMIN"),
}

# JSESSIONIDs that have been authenticated via j_security_check with a default
# credential in this (vuln) process. Shared across the request threads.
AUTHED_SESSIONS = set()
_LOCK = threading.Lock()

LOGIN_PAGE = (
    "<html><head><title>Tomcat Web Server Administration Tool</title></head>"
    "<body><h1>Tomcat Web Server Administration</h1>"
    "<form method='POST' action='/admin/j_security_check'>"
    "<input name='j_username'><input name='j_password' type='password'>"
    "</form></body></html>"
)

# Authenticated admin landing page — references the admin .do actions the NASL
# greps for (action.+(/admin/|')(commitChanges|logOut|setLocale)\.do).
BANNER_PAGE = (
    "<html><head><title>Tomcat Web Server Administration Tool</title></head>"
    "<body>"
    "<a href='/admin/commitChanges.do'>Commit Changes</a>"
    "<form action='/admin/logOut.do'></form>"
    "<form action='/admin/setLocale.do'></form>"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

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

    def _cookie_sid(self):
        cookie = self.headers.get("Cookie", "") or ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("JSESSIONID="):
                return part[len("JSESSIONID="):]
        return None

    def do_GET(self):
        path = self.path.split(";", 1)[0]  # strip ;jsessionid=...
        if path == "/admin/" or path == "/admin/index.jsp" or path == "/admin/login.jsp":
            # Login page, with the session cookie — served in both modes.
            self._send(200, LOGIN_PAGE,
                       extra_headers={"Set-Cookie": "JSESSIONID=%s; Path=/admin" % SESSION_ID})
        elif path == "/admin/banner.jsp":
            sid = self._cookie_sid()
            with _LOCK:
                authed = sid is not None and sid in AUTHED_SESSIONS
            if authed:
                # Authenticated admin UI — reached only with a logged-in session.
                self._send(200, BANNER_PAGE)
            else:
                # Not authenticated: Tomcat form-auth bounces back to the login page.
                self._send(200, LOGIN_PAGE,
                           extra_headers={"Set-Cookie": "JSESSIONID=%s; Path=/admin" % SESSION_ID})
        else:
            self._send(404, "Not found")

    def do_POST(self):
        path = self.path.split(";", 1)[0]
        if path == "/admin/j_security_check":
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            params = parse_qs(raw, keep_blank_values=True)
            user = (params.get("j_username", [""]) or [""])[0]
            pwd = (params.get("j_password", [""]) or [""])[0]
            sid = self._cookie_sid() or SESSION_ID

            if VULN_MODE and (user, pwd) in DEFAULT_CREDS:
                # Default credential accepted → authenticate the session and
                # redirect to the admin landing frame (NOT error.jsp).
                with _LOCK:
                    AUTHED_SESSIONS.add(sid)
                self._send(302, "", extra_headers={"Location": "/admin/mainFrame.jsp"})
            else:
                # Patched (or wrong creds): form-auth failure → error.jsp.
                self._send(302, "", extra_headers={"Location": "/admin/error.jsp"})
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
