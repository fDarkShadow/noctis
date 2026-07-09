#!/usr/bin/env python3
import os, ssl, threading, json
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SMARTERMAIL_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/api/upload":
            if VULN_MODE:
                data = json.dumps({
                    "fileName": "probe.aspx",
                    "key": "/noctis-probe/probe.aspx",
                    "success": True
                })
                self._send(200, data)
            else:
                self._send(401, json.dumps({"error": "Unauthorized"}))
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_GET(self): self._send(404, json.dumps({"error": "Not found"}))

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
