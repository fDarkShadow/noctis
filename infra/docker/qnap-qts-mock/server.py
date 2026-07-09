#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("QNAP_QTS_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, "<html><body><h1>QNAP NAS Login</h1></body></html>", "text/html")
        elif path == "/cgi-bin/quick/noctis47218probe":
            if VULN_MODE:
                self._send(200, "uid=0(root) gid=0(root) groups=0(root)\n")
            else:
                self._send(404, "Not found")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/cgi-bin/quick/quick.cgi":
            self._read_body()
            if VULN_MODE:
                self._send(200, '{"code": 200, "full_path_filename success": true}', "application/json")
            else:
                self._send(400, '{"code": 400, "error": "Invalid parameter"}', "application/json")
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
