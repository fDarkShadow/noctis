#!/usr/bin/env python3
# Mock for SolarWinds Storage Resource Monitor multiple SQL injection (CVE-2016-4350).
#
# Both modes serve a realistic SRM instance: /LoginServlet authenticates the
# probe credentials (HTTP 200 + "SolarWinds - Storage Manager" fingerprint +
# a JSESSIONID session cookie), and /DuplicateFilesServlet returns the
# authenticated "Enterprise Report" page (carrying the ">Enterprise Report<" /
# ">Storage Manager<" SRM fingerprint).
#
# Vuln mode: when the fileName parameter contains a single quote (the SQLi
# payload), /DuplicateFilesServlet reflects the injected value in a SQL error
# page -> the "SQL-INJECTION-TEST" marker appears. Only the real payload (the
# single quote) triggers the reflection.
# Patched mode: /DuplicateFilesServlet still serves the Enterprise Report page
# with the product fingerprint and a session cookie, but sanitises the input and
# never reflects the injection -> zero findings.
import os, ssl, threading
from urllib.parse import urlsplit, parse_qs, unquote
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SOLARWINDS_SRM_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

SESSION_COOKIE = "JSESSIONID=A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6; path=/"

LOGIN_PAGE = (
    "<html><head><title>SolarWinds - Storage Manager</title></head>"
    "<body><h1>SolarWinds - Storage Manager</h1>"
    "<p>Login successful.</p></body></html>"
)

def report_page(extra=""):
    return (
        "<html><head><title>Storage Manager</title></head><body>"
        "<div class='header'>&gt;Storage Manager&lt;</div>"
        "<h2>>Storage Manager<</h2><h1>>Enterprise Report<</h1>"
        "<div id='duplicate-files'>Duplicate Files Report</div>"
        f"{extra}</body></html>"
    )

SQL_ERROR_PAGE = report_page(
    "<div class='error'>java.sql.SQLException: "
    "You have an error in your SQL syntax near "
    "'SQL-INJECTION-TEST' at line 1</div>"
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

    def do_POST(self):
        if urlsplit(self.path).path == "/LoginServlet":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            # Authenticate the probe: loginState=checkLogin with a known user.
            if "loginState=checkLogin" in body and "loginName=admin" in body:
                self._send(200, LOGIN_PAGE,
                           extra_headers={"Set-Cookie": SESSION_COOKIE})
            else:
                self._send(401, "<html><body>Login failed</body></html>")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/DuplicateFilesServlet":
            # Require an authenticated session (the login cookie) to reach the
            # Enterprise Report, mirroring the NASL's authenticated flow.
            if "JSESSIONID=" not in (self.headers.get("Cookie") or ""):
                self._send(302, "", extra_headers={"Location": "/LoginServlet"})
                return
            file_name = unquote(parse_qs(parts.query).get("fileName", [""])[0])
            if VULN_MODE and "'" in file_name:
                # SQLi: the single quote breaks the query; the injected value is
                # reflected in the SQL error page.
                self._send(200, SQL_ERROR_PAGE)
            else:
                # Normal / patched: serve the report, no injection reflection.
                self._send(200, report_page())
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
