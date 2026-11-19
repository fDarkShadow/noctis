#!/usr/bin/env python3
"""Minimal CouchDB mock (HTTP 80 + HTTPS 443). vuln: admin party; patched: 401."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
VULN = os.environ.get("CDB_MODE", "patched") == "vuln"
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if not VULN:
            self._s(401, '{"error":"unauthorized","reason":"Authentication required."}'); return
        if self.path == "/_all_dbs":
            self._s(200, '["_replicator","_users","appdb"]')
        elif self.path == "/":
            self._s(200, '{"couchdb":"Welcome","version":"3.3.2"}')
        else:
            self._s(200, "{}")
def _https(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv
if __name__ == "__main__":
    http_port = int(os.environ.get("CDB_PORT", "80"))
    try:
        threading.Thread(target=_https(443).serve_forever, daemon=True).start()
    except Exception:
        pass  # no certs (local run) -> HTTP only
    HTTPServer(("0.0.0.0", http_port), H).serve_forever()
