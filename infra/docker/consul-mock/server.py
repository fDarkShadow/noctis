#!/usr/bin/env python3
"""Minimal Consul mock (HTTP 80 + HTTPS 443). vuln: catalog open; patched: 403."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
VULN = os.environ.get("CONSUL_MODE", "patched") == "vuln"
NODES = '[{"ID":"a1","Node":"consul-server-1","Address":"10.0.0.10","Datacenter":"dc1"}]'
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        b = body.encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if VULN and self.path.startswith("/v1/catalog"):
            self._s(200, NODES)
        else:
            self._s(403, "Permission denied")
def _https(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), H); srv.socket = ctx.wrap_socket(srv.socket, server_side=True); return srv
if __name__ == "__main__":
    try: threading.Thread(target=_https(443).serve_forever, daemon=True).start()
    except Exception: pass
    HTTPServer(("0.0.0.0", int(os.environ.get("CONSUL_PORT", "80"))), H).serve_forever()
