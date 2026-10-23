#!/usr/bin/env python3
"""Mock Webmin for CVE-2019-15107 (password_change.cgi unauthenticated RCE).

vuln:    POST /password_change.cgi with a pipe-injected `old`/`expired` field runs the
         command and reflects its output (uid=.. gid=..), mirroring Webmin 1.890-1.921.
patched: the same request returns the benign "incorrect password" page, no command output.
Serves HTTP:80 and HTTPS:443 (self-signed), per the noctis mock convention.
"""
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("WEBMIN_MODE", "patched") == "vuln"

# `old=test|id` / `expired=2|id` — a pipe inside either password field is the injection.
_INJECT_RE = re.compile(r"(?:old|expired)=[^&]*\|([^&]+)")
_ID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "MiniServ/1.920")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.split("?")[0] != "/password_change.cgi":
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        data = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        m = _INJECT_RE.search(data)
        if VULN_MODE and m and "id" in m.group(1):
            # command executed, output reflected — the real CVE-2019-15107 behaviour
            body = (
                "<html><body>Failed to change password : "
                "The current password is incorrect.\n" + _ID_OUTPUT + "\n"
                "</body></html>"
            )
            self._send(200, body)
        else:
            # patched (or non-injecting) request: benign error page, no command output
            self._send(
                200,
                "<html><body>Failed to change password : "
                "The current password is incorrect.</body></html>",
            )

    def do_GET(self):
        if self.path.split("?")[0] == "/session_login.cgi":
            self._send(200, "<html><body>Login to Webmin</body></html>")
        else:
            self._send(200, "<html><body>Webmin</body></html>")


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
