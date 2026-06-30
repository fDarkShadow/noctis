#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("STRUTS_50164_MODE", "patched") == "vuln"

_file_uploaded = False


def _read_body(handler):
    length = int(handler.headers.get("Content-Length", 0))
    return handler.rfile.read(length) if length > 0 else b""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/noctis_probe.txt":
            if _file_uploaded:
                self._send(200, "noctis-cve-2023-50164-probe")
            else:
                self._send(404, "Not found")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        global _file_uploaded
        _read_body(self)
        if self.path.startswith("/upload.action"):
            if VULN_MODE:
                _file_uploaded = True
                self._send(200, '{"status":"success","file":"uploaded"}', "application/json")
            else:
                self._send(400, "Invalid filename: path traversal not allowed")
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
