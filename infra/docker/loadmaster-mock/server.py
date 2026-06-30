#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("LOADMASTER_MODE", "patched") == "vuln"

VULN_BODY = (
    "WWW-Authenticate: Basic realm=\"LoadMaster\"\n"
    "bin\nboot\ndev\netc\nhome\nlib\nmnt\nproc\ntmp\nusr\nvar\n"
)

PATCHED_BODY = "WWW-Authenticate: Basic realm=\"LoadMaster\"\n"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/access/set"):
            if VULN_MODE:
                self._send(200, VULN_BODY)
            else:
                self._send(401, PATCHED_BODY)
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()

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
