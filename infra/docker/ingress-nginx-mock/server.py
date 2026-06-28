#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("INGRESS_MODE", "patched") == "vuln"

VULN_BODY = (
    b'{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",'
    b'"response":{"uid":"noctis-probe","allowed":false,"status":{'
    b'"message":"nginx: [emerg] directive is specified too late in'
    b' load_module /tmp/noctis.so"}}}'
)

PATCHED_BODY = (
    b'{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview",'
    b'"response":{"uid":"noctis-probe","allowed":false,"status":{'
    b'"message":"Invalid Ingress configuration"}}}'
)


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
        body = self.rfile.read(length) if length > 0 else b""
        if VULN_MODE and b"load_module" in body:
            self._send(200, VULN_BODY)
        else:
            self._send(200, PATCHED_BODY)

    def do_GET(self):
        self._send(200, b"OK", "text/plain")


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
