#!/usr/bin/env python3
import json, os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("NAKIVO_MODE", "patched") == "vuln"

# ASCII byte array for "root:x:0:0:root:/root:/bin/bash\n"
PASSWD_BYTES = [114,111,111,116,58,120,58,48,58,48,58,114,111,111,116,58,47,114,111,111,116,58,47,98,105,110,47,98,97,115,104,10]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(',', ':')).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        if self.path == "/c/router":
            if not VULN_MODE:
                self._send(401, {"type":"rpc","tid":1,"result":None,"message":"Authentication required"})
                return

            try:
                req = json.loads(raw)
            except Exception:
                self._send(400, {"type":"rpc","tid":1,"result":None,"message":"Invalid JSON"})
                return

            action = req.get("action", "")
            method = req.get("method", "")
            data = req.get("data", [])

            if action == "STPreLoadManagement" and method == "getImageByPath" and data and data[0] == "/etc/passwd":
                self._send(200, {"type":"rpc","tid":req.get("tid",1),"action":action,"method":method,"result":PASSWD_BYTES})
            else:
                self._send(200, {"type":"rpc","tid":req.get("tid",1),"result":None,"message":"Not found"})
        else:
            self._send(404, {"error":"Not found"})

    def do_GET(self):
        self._send(404, {"error":"Not found"})

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
