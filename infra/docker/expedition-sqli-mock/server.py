#!/usr/bin/env python3
import os, ssl, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VULN_MODE = os.environ.get("EXPEDITION_SQLI_MODE", "patched") == "vuln"

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
        action = params.get("action", [""])[0]
        ptype = params.get("type", [""])[0]

        if self.path == "/bin/configurations/parsers/Checkpoint/CHECKPOINT.php":
            if action == "get" and ptype == "existing_ruleBases":
                self._send(200, b'{"ruleBasesNames":["DefaultRule","HighPriority"],"status":"ok"}')
            elif "SLEEP" in raw_str:
                if VULN_MODE:
                    time.sleep(6)
                self._send(200, b'{"status":"imported","count":0}')
            else:
                self._send(200, b'{"status":"ok"}')
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
