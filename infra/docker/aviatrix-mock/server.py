#!/usr/bin/env python3
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import urllib.request

VULN_MODE = os.environ.get("AVIATRIX_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        raw_str = raw.decode()
        params = parse_qs(raw_str)
        cloud_type = params.get("cloud_type", [""])[0]

        if self.path == "/v1/api":
            if VULN_MODE:
                if "|curl" in cloud_type:
                    m = re.search(r'http://\S+', cloud_type)
                    if m:
                        try:
                            urllib.request.urlopen(m.group(0), timeout=5)
                        except Exception:
                            pass
                    self._send(200, b'{"return":true,"reason":"","results":[]}')
                elif cloud_type == "1":
                    self._send(200, b'{"return":true,"reason":"","results":["us-east-1","us-west-2"]}')
                else:
                    self._send(200, b'{"return":true,"reason":"","results":[]}')
            else:
                if any(c in cloud_type for c in ["|", ";", "$", "`"]):
                    self._send(400, b'{"return":false,"reason":"Invalid cloud_type parameter"}')
                else:
                    self._send(200, b'{"return":false,"reason":"Authentication required"}')
        else:
            self._send(404, b'{"error":"Not found"}')

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
