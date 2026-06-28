#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BIGIP_MODE", "patched") == "vuln"

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
        if self.path == "/mgmt/tm/util/bash":
            if VULN_MODE:
                resp = json.dumps({
                    "kind": "tm:util:bash:runstate",
                    "commandResult": "NOCTIS_BIGIP_RCE_CONFIRMED\n"
                })
                self._send(200, resp)
            else:
                self._send(401, json.dumps({"code": 401, "message": "Unauthorized"}))
        else:
            self._send(404, json.dumps({"code": 404, "message": "Not found"}))

    def do_GET(self):
        self._send(404, json.dumps({"code": 404, "message": "Not found"}))

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
