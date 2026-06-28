#!/usr/bin/env python3
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("MINIO_MODE", "patched") == "vuln"


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
        if self.path == "/minio/bootstrap/v1/verify":
            if VULN_MODE:
                payload = json.dumps({
                    "MinioEnv": {
                        "MINIO_ROOT_USER": "minio_admin",
                        "MINIO_ROOT_PASSWORD": "secret_key_noctis_test",
                        "MINIO_VOLUMES": "/data",
                        "MINIO_SITE_NAME": "noctis-test-cluster",
                    }
                })
                self._send(200, payload)
            else:
                self._send(403, '{"error":"Forbidden"}')
        else:
            self._send(404, '{"error":"Not found"}', "text/plain")

    def do_GET(self):
        self._send(404, '{"error":"Not found"}', "text/plain")


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
