#!/usr/bin/env python3
import os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("MIRTH_MODE", "patched") == "vuln"

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
        if self.path == "/api/server/version":
            if VULN_MODE:
                self._send(200, "4.3.0")
            else:
                self._send(200, "4.4.1")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/api/users":
            if not VULN_MODE:
                self._send(401, "Unauthorized")
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            # Extract OOB URL from curl command in XML and call back
            match = re.search(r'curl (http://[^\s<"]+)', body)
            if match:
                oob_url = match.group(1)
                try:
                    urllib.request.urlopen(oob_url, timeout=5)
                except Exception:
                    pass
            self._send(500, "java.io.StreamCorruptedException: invalid stream header")
        else:
            self._send(404, "Not found")

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
