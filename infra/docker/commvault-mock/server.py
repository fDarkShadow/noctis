#!/usr/bin/env python3
import os, ssl, threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VULN_MODE = os.environ.get("COMMVAULT_MODE", "patched") == "vuln"

ERROR_BODY = b'{"error":"Invalid commcell"}'
FORBIDDEN = b'{"error":"Forbidden"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/commandcenter/deployWebpackage.do":
            self._send(404, b'{"error":"Not found"}')
            return
        if not VULN_MODE:
            self._send(403, FORBIDDEN)
            return
        raw = self._read_body()
        params = parse_qs(raw.decode(errors="replace"))
        commcell = params.get("commcellName", [""])[0]
        if commcell.startswith("http://") or commcell.startswith("https://"):
            try:
                urllib.request.urlopen(commcell, timeout=5)
            except Exception:
                pass
        self._send(900, ERROR_BODY)

    def do_GET(self):
        self._send(404, b'{"error":"Not found"}')


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
