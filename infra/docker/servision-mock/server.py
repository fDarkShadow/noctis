#!/usr/bin/env python3
"""Mock for CVE-2015-0930 (servision) — OpenVAS NASL 2016/gb_servision_hvg_default_cred_vuln.nasl (GPL-2.0-only).

Faithful NASL flow:
  GET /index.htm  -> login form carrying both user_username and user_password (product gate, both modes)
  POST /index.htm -> on default creds: HTTP 201 + Set-Cookie (vuln only); patched answers 401
  GET /top.htm    -> 200 + "Logout" only when the request carries the issued cookie (vuln only); else 401
"""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
VULN = os.environ.get("SERVISION_MODE", "patched") == "vuln"
COOKIE = "SVNSESSION=0a1b2c3d"
LOGIN_FORM = ('<html><body><form method="post" action="/index.htm">'
              '<input name="user_username"><input name="user_password" type="password">'
              '<input type="submit"></form></body></html>')
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
        if p == "/index.htm":
            return self._s(200, LOGIN_FORM)                 # product/login page, both modes
        if p == "/top.htm":
            ck = self.headers.get("Cookie", "")
            if VULN and COOKIE in ck:
                return self._s(200, "<html><body>HVG dashboard. <a href='/logout'>Logout</a></body></html>")
            return self._s(401, "<html><body>Unauthorized</body></html>")
        return self._s(404, "Not found")
    def do_POST(self):
        p = self.path.split("?")[0]; data = self._body()
        if p == "/index.htm":
            if VULN and "user_username=admin" in data and "user_password=Bantham" in data:
                return self._s(201, "<html><body>Authentication successful.</body></html>",
                               hdrs={"Set-Cookie": COOKIE + "; path=/"})
            return self._s(401, "<html><body>Invalid credentials.</body></html>")
        return self._s(404, "Not found")
def _https(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True); return srv
if __name__ == "__main__":
    threading.Thread(target=_https(443).serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), H).serve_forever()
