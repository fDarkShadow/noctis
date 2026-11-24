#!/usr/bin/env python3
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

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


if __name__ == "__main__":
    serve(Handler, HTTPServer)
