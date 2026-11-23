#!/usr/bin/env python3
"""Mock for Oracle E-Business Suite IESFOOTPRINT SQL injection (CVE-2017-3549).

vuln  : /OA_HTML/iesfootprint.jsp reflects the injected request parameters into
        an authenticated-looking Oracle Applications page (SQLi marker present).
patched: iesfootprint.jsp returns 404 without the reflected content.
Both modes serve the AppsLocalLogin.jsp login page used by the preliminary probe.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ORACLE_EBS_MODE", "patched") == "vuln"

LOGIN_PAGE = (
    "<html><head><title>Login</title>"
    '<meta name="generator" content="Oracle UIX"></head>'
    "<body>Oracle E-Business Suite Login</body></html>"
)

VULN_PAGE = (
    "<html><head><title>Oracle Applications</title></head><body>"
    "<a href=\"/OA_HTML/OALogout.jsp\">Sign Out</a>"
    "<h1>Oracle Applications</h1>"
    "<div>dscriptId=<>SQL Injection Test</div>"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "JSESSIONID=0000noctismock; path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path preserves the %3C%3E encoding of the raw tcp_connect request.
        path = self.path
        if path.startswith("/OA_HTML/AppsLocalLogin.jsp"):
            self._send(200, LOGIN_PAGE)
            return
        if path.startswith("/OA_HTML/iesfootprint.jsp"):
            if VULN_MODE:
                self._send(200, VULN_PAGE)
            else:
                self._send(404, "Not found")
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
