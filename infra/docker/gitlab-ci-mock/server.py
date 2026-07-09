#!/usr/bin/env python3
import json, os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import urlopen

VULN_MODE = os.environ.get("GITLAB_MODE", "patched") == "vuln"

HOMEPAGE = b"<html><head><title>GitLab</title></head><body>Welcome to GitLab</body></html>"
LINT_OK = b'{"status":"valid","errors":[],"warnings":[]}'
LINT_BLOCKED = b'{"status":"invalid","errors":["Remote includes are not allowed"],"warnings":[]}'
REMOTE_RE = re.compile(r"remote:\s*'([^']+)'")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            if VULN_MODE:
                self._send(200, HOMEPAGE)
            else:
                self._send(403, b"Forbidden")
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/api/v4/ci/lint":
            self._send(404, b"Not found")
            return

        raw = self._read_body()
        if not VULN_MODE:
            self._send(200, LINT_BLOCKED, "application/json")
            return

        try:
            data = json.loads(raw)
            content = data.get("content", "")
            m = REMOTE_RE.search(content)
            if m:
                try:
                    urlopen(m.group(1), timeout=5)
                except Exception:
                    pass
        except Exception:
            pass

        self._send(200, LINT_OK, "application/json")


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
