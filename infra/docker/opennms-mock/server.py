#!/usr/bin/env python3
# OpenNMS < 14.0.3 Default Credentials mock (CVE-2015-0975 / CVE-2015-7856).
#
# Reproduces the Spring-Security login flow the OpenVAS NASL exercises:
#   GET  /opennms/login.jsp               -> 200, OpenNMS fingerprint + JSESSIONID
#   POST /opennms/j_spring_security_check -> login with j_username / j_password
#   GET  /opennms/frontPage.htm           -> authenticated console landing page
#
# vuln mode    : the default rtc/rtc account is enabled. A correct rtc/rtc POST
#                returns 302 -> /opennms/index.jsp (no ?login_error), and the
#                authenticated frontPage.htm is served (with the required markers)
#                to a request carrying a session cookie.
# patched mode : the product is served identically (same login.jsp fingerprint,
#                same JSESSIONID cookie) but the default account is disabled, so
#                EVERY credential — including rtc/rtc — is rejected with
#                302 -> /opennms/login.jsp?login_error=1, and frontPage.htm
#                redirects unauthenticated sessions back to the login page.
# Only the real rtc/rtc credentials unlock the authenticated area in vuln mode,
# so the true-positive proves the default credentials matter, not that a cookie
# or the product is present.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("OPENNMS_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

SESSION_ID = "A1b2C3d4E5f6G7h8I9j0K1l2"

LOGIN_PAGE = (
    "<html><head><title>OpenNMS Web Console - Login</title></head>"
    "<body><div id='login-box'><form action='j_spring_security_check' method='post'>"
    "<input name='j_username'><input name='j_password' type='password'>"
    "</form></div>"
    "<div id='footer'>Copyright &copy; 2002-2015 The OpenNMS Group, Inc. OpenNMS&reg; "
    "is a registered trademark of The OpenNMS Group, Inc.</div></body></html>"
)

FRONT_PAGE = (
    "<html><head><title>OpenNMS Web Console</title></head><body>"
    "<ul id='o-menu'>"
    "<li><a href='rtc/index.jsp'>Statistics</a></li>"
    "<li><a href='dashboard.jsp'>Dashboard</a></li>"
    "<li><a href='account/selfService/newPasswordEntry'>Change Password</a></li>"
    "<li><a href='j_spring_security_logout'>Log Out</a></li>"
    "</ul>"
    "<div id='content'><h3>Nodes with Outages</h3></div>"
    "<div id='footer'>Copyright &copy; 2002-2015 "
    "<a href='http://www.opennms.com/'>The OpenNMS Group, Inc.</a> "
    "OpenNMS&reg; is a registered trademark.</div></body></html>"
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

    def _has_session(self):
        return "JSESSIONID=" in self.headers.get("Cookie", "")

    def do_GET(self):
        if self.path == "/opennms/login.jsp":
            # Product fingerprint + session cookie — served in BOTH modes.
            self._send(200, LOGIN_PAGE, extra_headers={
                "Set-Cookie": "JSESSIONID=%s; Path=/opennms; HttpOnly" % SESSION_ID})
        elif self.path == "/opennms/frontPage.htm":
            # Authenticated console — only reachable once logged in (vuln mode,
            # where rtc/rtc succeeded). An unauthenticated / patched session is
            # redirected back to the login page, so no markers leak.
            if VULN_MODE and self._has_session():
                self._send(200, FRONT_PAGE)
            else:
                self._send(302, "", extra_headers={
                    "Location": "/opennms/login.jsp"})
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/opennms/j_spring_security_check":
            length = int(self.headers.get("Content-Length", 0) or 0)
            data = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            params = {}
            for pair in data.split("&"):
                if "=" in pair:
                    k, _, val = pair.partition("=")
                    params[k] = val
            user = params.get("j_username", "")
            pw = params.get("j_password", "")
            if VULN_MODE and user == "rtc" and pw == "rtc":
                # Default account active -> successful login.
                self._send(302, "", extra_headers={
                    "Location": "/opennms/index.jsp",
                    "Set-Cookie": "JSESSIONID=%s; Path=/opennms; HttpOnly" % SESSION_ID})
            else:
                # Default account disabled (patched) or wrong creds -> rejected.
                self._send(302, "", extra_headers={
                    "Location": "/opennms/login.jsp?login_error=1"})
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
