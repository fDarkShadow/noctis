#!/usr/bin/env python3
"""Mock for CVE-2004-1647 (password-protect) — OpenVAS NASL pre2008/passwordprotect_sql_inject.nasl (GPL-2.0-only).

Faithful NASL flow:
  GET  /adminSection/main.asp        -> issues a session cookie; non-admin page (both modes)
  POST /adminSection/index_next.asp  -> SQLi auth bypass authenticates THAT cookie (vuln only); patched 401
  GET  /adminSection/main.asp (cookie) -> admin page only for an authenticated cookie (vuln only)
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
VULN = os.environ.get("PASSWORD_PROTECT_MODE", "patched") == "vuln"
COOKIE = "ASPSESSIONIDQABBCCDD=sessabc"
INJECTION = "%27+or+%27%27%3D%27"           # admin=' or ''='
AUTHED = set()                              # cookies the SQLi has authenticated
ADMIN = ("<html><body><h1>Web Site Administration</h1>"
         "<p>The Web Animations Administration Section</p></body></html>")
LOGIN = "<html><body><form method='post'>Please log in.</form></body></html>"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, b, hdrs=None, ct="text/html"):
        if isinstance(b, str): b = b.encode()
        self.send_response(code); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (hdrs or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("latin1") if n else ""
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/adminSection/main.asp":
            ck = self.headers.get("Cookie", "")
            if VULN and ck in AUTHED:
                return self._s(200, ADMIN)                       # authenticated session
            return self._s(200, LOGIN, hdrs={"Set-Cookie": COOKIE + "; path=/"})
        return self._s(404, "Not found")
    def do_POST(self):
        p = self.path.split("?")[0]; data = self._body()
        if p == "/adminSection/index_next.asp":
            ck = self.headers.get("Cookie", "")
            if VULN and INJECTION in data:
                AUTHED.add(ck)                                   # SQLi bypass authenticates this cookie
                return self._s(200, "<html><body>Logged in.</body></html>")
            return self._s(401, "<html><body>Access denied.</body></html>")
        return self._s(404, "Not found")
def _https(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True); return srv
if __name__ == "__main__":
    threading.Thread(target=_https(443).serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), H).serve_forever()
