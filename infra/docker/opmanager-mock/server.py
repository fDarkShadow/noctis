#!/usr/bin/env python3
"""Mock for CVE-2015-7765. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial. The vuln login issues
a RANDOM JSESSIONID and the dashboard serves content only when that exact session comes back, so
the feed's cookie-extraction + Cookie-header steps are genuinely exercised (not a shared constant)."""
import os, secrets, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN = os.environ.get("CVE_2015_7765_MODE", "patched") == "vuln"
SESSION = secrets.token_hex(8).upper()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _start(self, code):
        self._body = b""
        self._code = code
        self._hdrs = []

    def _h(self, k, v):
        self._hdrs.append((k, v))

    def _finish(self, body):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        self.send_response(self._code)
        for k, v in self._hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("latin-1", "replace") if n else ""

    def _route(self, method):
        path = self.path
        body = self._read_body()
        vuln = VULN
        cookie = self.headers.get("Cookie", "")
        if (vuln and method == 'POST' and path == '/jsp/Login.do'
                and 'userName=IntegrationUser' in body and 'password=plugin' in body):
            self._start(302)
            self._h('Set-Cookie', 'JSESSIONID=' + SESSION + '; Path=/')
            self._h('Location', '/index.jsp')
            self._finish('')
            return
        if (vuln and path == '/apiclient/ember/index.jsp'
                and ('JSESSIONID=' + SESSION) in cookie):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish("<html><head><title>OpManager</title></head><body><div id='HomeDashboard'>OpManager Home</div><a href='/jsp/Logout.do'>Logout.do</a></body></html>\n")
            return
        if (vuln and path == '/apiclient/ember/index.jsp'):
            self._start(302)
            self._h('Location', '/jsp/Login.do')
            self._finish('')
            return
        if (method == 'POST' and path == '/jsp/Login.do'):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish('<html><head><title>OpManager - Login</title></head><body><form>Invalid user name or password</form></body></html>\n')
            return
        if (path == '/apiclient/ember/index.jsp'):
            self._start(302)
            self._h('Location', '/jsp/Login.do')
            self._finish('')
            return
        # default
        self._start(404)
        self._h("Content-Type", "text/plain")
        self._finish("Not found\n")

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


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
