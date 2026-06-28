#!/usr/bin/env python3
import os
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BIGIP_46747_MODE", "patched") == "vuln"

# Shared user store simulating BIG-IP user database.
# Populated by the AJP-smuggled POST to /tmui/login.jsp in vuln mode.
_lock = threading.Lock()
_user_store = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain", headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def do_GET(self):
        if self.path == "/tmui/login.jsp":
            # BIG-IP fingerprint page — always returned regardless of mode
            html = (
                "<html><head><title>BIG-IP&reg; Configuration Utility</title></head>"
                "<body><p>F5 Networks BIG-IP</p></body></html>"
            )
            self._send(200, html, ct="text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/tmui/login.jsp":
            te = self.headers.get("Transfer-Encoding", "")
            body = self._read_body()
            if VULN_MODE and "chunked" in te.lower():
                # Simulate AJP-smuggled user creation
                params = dict(urllib.parse.parse_qsl(body))
                name = params.get("name", "")
                password = params.get("password", "")
                if name:
                    with _lock:
                        _user_store[name] = password
                self._send(302, "Found", headers={"Location": "/tmui/login.jsp"})
            else:
                self._send(403, "Forbidden")

        elif self.path == "/mgmt/shared/authn/login":
            import json
            body = self._read_body()
            try:
                data = json.loads(body)
                username = data.get("username", "")
                password = data.get("password", "")
            except (json.JSONDecodeError, ValueError):
                username, password = "", ""

            with _lock:
                stored_pw = _user_store.get(username)

            if stored_pw is not None and stored_pw == password:
                token_body = json.dumps({
                    "token": {
                        "token": "AAAA1234AAAA1234AAAA1234AAAA1234",
                        "name": username,
                        "kind": "shared:authz:tokens:authtokenitemstate",
                    }
                })
                self._send(200, token_body, ct="application/json")
            else:
                self._send(401, json.dumps({"code": 401, "message": "Unauthorized"}),
                           ct="application/json")

        else:
            self._send(404, "Not found")


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
