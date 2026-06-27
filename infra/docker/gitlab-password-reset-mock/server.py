#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote_plus

VULN_MODE = os.environ.get("GITLAB_MODE", "vuln") == "vuln"

CSRF_TOKEN = "test_csrf_token_noctis_12345"

def _sign_in_html():
    return f"""<!DOCTYPE html>
<html>
<head><title>Sign in · GitLab</title></head>
<body>
  <form action="/users/sign_in" method="post">
    <input type="hidden" name="authenticity_token" value="{CSRF_TOKEN}" />
    <input type="text" name="user[login]" />
    <input type="password" name="user[password]" />
    <button type="submit">Sign in</button>
  </form>
</body>
</html>""".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type="text/html; charset=utf-8", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/users/sign_in":
            self._send(200, _sign_in_html())
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/users/password":
            self._send(404, b"Not Found")
            return

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")

        # Detect array email syntax: user[email][] appears more than once
        # or the key ends with []
        params = parse_qs(raw_body, keep_blank_values=True)
        has_array_email = "user[email][]" in params and len(params["user[email][]"]) > 1

        if VULN_MODE and has_array_email:
            # Vulnerable: accept multi-email array, redirect to sign_in
            self._send(302, b"", extra_headers={"Location": "/users/sign_in"})
        else:
            # Patched or no array syntax: reject with 200 (form re-render)
            self._send(200, b"<html><body>Email is invalid</body></html>")


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/cert/server.crt", "/cert/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    http_srv = HTTPServer(("0.0.0.0", 80), Handler)
    https_srv = _make_https_server(443)
    threading.Thread(target=https_srv.serve_forever, daemon=True).start()
    http_srv.serve_forever()
