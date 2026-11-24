#!/usr/bin/env python3
"""Mock for CVE-2017-8917. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial. The login view issues a
RANDOM session cookie and CSRF token, and the vuln com_fields handler returns the XPATH error only
when both come back — so the feed's cookie/token extraction is genuinely exercised. The XPATH
error quotes are HTML-escaped (&#039;), exactly as real Joomla renders them."""
import os, secrets, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN = os.environ.get("CVE_2017_8917_MODE", "patched") == "vuln"
COOKIE_NAME = secrets.token_hex(16)
COOKIE_VAL = secrets.token_hex(16)
TOKEN = secrets.token_hex(16)


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
        has_session = (COOKIE_NAME + "=" + COOKIE_VAL) in cookie
        has_token = (TOKEN + "=1") in path
        if (method == 'GET' and path.startswith('/index.php/component/users')):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._h('Set-Cookie', COOKIE_NAME + '=' + COOKIE_VAL + '; path=/')
            self._finish('<html><body><form><fieldset><input type="hidden" name="'
                         + TOKEN + '" value="1"></fieldset></form></body></html>\n')
            return
        # Vulnerable com_fields handler: only errors out when the real session + token are carried,
        # and escapes the quotes around the computed :255: marker exactly as Joomla does.
        if (vuln and 'com_fields' in path and has_session and has_token):
            self._start(500)
            self._h('Content-Type', 'text/html')
            self._finish("<html><title>Home Page</title><body>Home Page<br>"
                         "1064 - XPATH syntax error: &#039;:255:&#039;</body></html>\n")
            return
        if ('com_fields' in path):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish('<html><body>Home Page<br>Invalid field context, request ignored.</body></html>\n')
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
