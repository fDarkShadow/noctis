#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("GITLAB_MODE", "vuln") == "vuln"

# A known-vulnerable CSS hash (GitLab 13.10.1, from the Nuclei template hash list)
VULN_HASH = "015d088713b23c749d8be0118caeb21039491d9812c75c913f48d53559ab09df"
# A hash that is NOT in the vulnerable list (patched release)
PATCHED_HASH = "00000000000000000000000000000000000000000000000000000000deadbeef"

def _sign_in_html(css_hash):
    return f"""<!DOCTYPE html>
<html>
<head>
  <title>Sign in · GitLab</title>
  <link rel="stylesheet" href="/assets/application-{css_hash}.css" />
</head>
<body>
  <div class="login-page">
    <h1>Sign in</h1>
    <form action="/users/sign_in" method="post">
      <input type="text" name="user[login]" />
      <input type="password" name="user[password]" />
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>""".encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, content_type="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/users/sign_in":
            css_hash = VULN_HASH if VULN_MODE else PATCHED_HASH
            self._send(200, _sign_in_html(css_hash))
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        self._send(302, b"", content_type="text/plain")
        self.send_header("Location", "/users/sign_in")


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
