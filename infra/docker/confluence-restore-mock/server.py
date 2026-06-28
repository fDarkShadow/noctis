#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("CONFLUENCE_MODE", "patched") == "vuln"

ERROR_BODY = json.dumps({
    "status": "error",
    "message": "The zip file did not contain an entry for exportDescriptor.properties"
})

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

        atlassian_token = self.headers.get("X-Atlassian-Token", "")

        if self.path == "/json/setup-restore.action":
            if VULN_MODE and atlassian_token == "no-check":
                self._send(200, ERROR_BODY)
            else:
                self._send(302, b"", extra_headers={"Location": "/login.action?permissionViolation=true"})
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_GET(self):
        if self.path in ("/", "/index.action"):
            self._send(302, b"", extra_headers={"Location": "/login.action"})
        elif self.path == "/login.action":
            page = b"<html><head><title>Atlassian Confluence</title></head><body><h1>Log In</h1></body></html>"
            self._send(200, page, ct="text/html")
        else:
            self._send(404, json.dumps({"error": "Not found"}))

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
